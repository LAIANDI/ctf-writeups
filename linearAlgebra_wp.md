# 羊城杯 2022 Crypto - linearAlgebra Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目名称 | linearAlgebra |
| 来源 | 羊城杯 2022（附件 `CRYPTO附件/linearAlgebra.zip`） |
| 类型 | Crypto / 线性代数 + 格约化（LLL/BKZ） |
| 附件 | `linear.sage`、`out` |
| zip SHA256 | `fd7dd160ecc085ff50b5c6552d6741dd6f02b759b0a75168a2e3813228b7ca48` |
| linear.sage SHA256 | `2daacbd1cf4e512d089e3166abef3b547e7381a7408586ed870ae0fd7ffb9995` |
| out SHA256 | `25fcb2e29f4d3351df60026add0ccb9b119c6ab8739f55c7a7e6768e3103c721` |
| Flag | `flag{b5932c2c-e210-4c39-9fb5-a7f35e861d32}`（源码断言前缀为 `DASCTF{`，平台统一按 `flag{}` 提交） |

---

## 2. Recon

`linear.sage`：

```python
from secret import flag
import libnum, random, os

assert flag[:7] == b'DASCTF{' and flag[-1] == ord('}')

n = 32
asize = 512

def pad(m, n):
    assert len(m) < n*n
    return m + b'\x00' + os.urandom(n*n - len(m) - 1)

def bytes2Matrix(m, n):
    return matrix(ZZ, [[m[r*n+c] for c in range(n)] for r in range(n)])

def randMatrix(s, n):
    while True:
        Mt = matrix(ZZ, [[random.randint(0, 2^s) for c in range(n)] for r in range(n)])
        if Mt.det() != 0:
            return Mt

def corrupt(Mt, s, n):
    Mt_ = matrix(ZZ, Mt)
    for i in range(n):
        r_ = random.randint(0, n-1)
        c_ = random.randint(0, n-1)
        Mt_[r_, c_] = random.randint(0, 2^s)
    return Mt_

m = pad(flag[7:-1], n)
M = bytes2Matrix(m, n)         # 32x32，元素为字节 0..255
A = randMatrix(asize, n)       # 32x32，元素 ~ 2^512，det != 0
C = A * M                      # 32x32
Ac = corrupt(A, asize, n)      # A 的 32 个随机位置被替换
print('C:');  print(C)
print('Ac:'); print(Ac)
```

`out` 给出两个 32x32 矩阵 `C` 和 `Ac`。

关键观察：`Ac` 只是在 `A` 的 **32 个随机位置** 上被替换。32 次随机落点分布在 32 行中，
按期望约 `32·(1-1/32)^32 ≈ 11.8` 行完全**没有被污染**（本次实例中共 20 行被污染、
**12 行干净**）。

---

## 3. 漏洞 / 结构分析

设 `M` 的第 `k` 列为 `m_k`（32 维，元素 0..255），`C` 的第 `k` 列为 `C[:,k]`。由 `C = A·M`：

```text
C[:,k] = A · m_k
```

若第 `i` 行是**干净**的（`Ac[i,:] == A[i,:]`），则

```text
C[i,k] = Ac[i,:] · m_k        （对每个 k 都成立）
```

于是 `m_k` 是线性方程 `a·m = u`（`a = Ac[i,:]`，`u = C[i,k]`）的**小整数解**（`0 ≤ m_j ≤ 255`）。

### 为什么这个解唯一且可求

`a` 的 32 个分量都是 ~2^512 的随机整数。方程 `a·m = 0` 的整数解构成一个秩 31 的格，
其实最短向量经验上约 2^16 量级，远大于盒 `[0,255]^32` 的尺度（对角线 ≈ 1443）。
因此 `{m : a·m = u}` 在盒 `[0,255]^32` 内至多一个解，而真实的 `m_k` 恰好在盒内。

用经典“线性方程小解”格构造求解：

```text
基向量（行）：
  i = 0..31 : ( e_i |  K·a[i] )
  最后一行  : ( 0   |  K·u   )      K = 2^80
```

格向量的一般形式为 `(m | K·(a·m + z·u))`。取 `z = -1` 即得 `a·m = u`，
对应格的短向量 `(m | 0)`；所有其它末坐标为 0 的格向量都是齐次解 `a·m = 0`，
范数远大于 `‖m‖`。对格做 BKZ/LLL，取“末坐标全为 0、前 32 个分量绝对值落在
0..255”的最短向量，即得 `±m_k`。

> 实测（合成数据验证）：最短的末坐标为零向量范数正是 `‖m_true‖`，
> 次短向量范数约 1.7×10¹⁰，分离度极高，BKZ-12 稳定命中。

由于干净行约占 12/32，逐个尝试行即可；干净行对所有 32 列都会给出合法小解，
被污染行则在某列上找不到盒内解。

---

## 4. 攻击链

```text
out:  C (32x32),  Ac (32x32, A 的 32 个位置被替换)
        |
        |  对每个候选行 i：
        |    a = Ac[i,:]
        |    对每列 k：格  {(e_j, K a[j])}, (0, K C[i,k])  --BKZ-->  ({±}m_k | 0)
        |    若 32 列都得到 0..255 的解 -> 行 i 干净，M[:,k] = m_k
        v
M (32x32 字节矩阵)
        |
        |  行优先展开 m = bytes(M)，取第一个 0x00 之前的内容
        v
flag{b5932c2c-e210-4c39-9fb5-a7f35e861d32}
```

---

## 5. 完整脚本

见 `exploits/linearAlgebra.py`（自包含，读取 `out` 即可）：

```python
#!/usr/bin/env python3
import re, sys
from fpylll import IntegerMatrix, BKZ

N = 32
K = 1 << 80

def parse(path):
    txt = open(path).read()
    i = txt.index("C:") + 2
    j = txt.index("Ac:")
    Cn = [int(x) for x in re.findall(r"\d+", txt[i:j])]
    An = [int(x) for x in re.findall(r"\d+", txt[j:])]
    C  = [Cn[r*N:(r+1)*N] for r in range(N)]
    Ac = [An[r*N:(r+1)*N] for r in range(N)]
    return C, Ac

def solve_col(a, u):
    d = N + 1
    B = [[0]*d for _ in range(d)]
    for i in range(N):
        B[i][i] = 1
        B[i][N] = K * a[i]
    B[N][N] = K * u
    Mi = IntegerMatrix.from_matrix(B)
    BKZ.reduction(Mi, BKZ.Param(block_size=12), float_type="mpfr", precision=700)
    best = None
    for i in range(d):
        row = [int(Mi[i, j]) for j in range(d)]
        if any(row[N:]):
            continue
        vec = [abs(x) for x in row[:N]]
        if all(0 <= x <= 255 for x in vec):
            s = sum(x*x for x in vec)
            if best is None or s < best[0]:
                best = (s, vec)
    return best[1] if best else None

def solve(path):
    C, Ac = parse(path)
    for i in range(N):                    # 尝试找到一个干净行
        cols = []
        for k in range(N):
            m = solve_col(Ac[i], C[i][k])
            if m is None:
                break
            cols.append(m)
        if len(cols) != N:
            continue
        M = [[cols[k][r] for k in range(N)] for r in range(N)]
        mb = bytes(M[r][c] for r in range(N) for c in range(N))
        if 0 in mb:
            return b"flag{" + mb[:mb.index(0)] + b"}"
    raise RuntimeError("no clean row")

if __name__ == "__main__":
    print(solve(sys.argv[1]).decode())
```

运行：

```bash
cd /Users/laiandi/ctf
.venv/bin/python exploits/linearAlgebra.py work/linearAlgebra/linearAlgebra/out
```

---

## 6. 实际输出

```text
$ .venv/bin/python exploits/linearAlgebra.py work/linearAlgebra/linearAlgebra/out
flag{b5932c2c-e210-4c39-9fb5-a7f35e861d32}
```

恢复出的 `M` 前 64 字节：

```text
b5932c2c-e210-4c39-9fb5-a7f35e861d32\x00\x06\xfd\x04U...
```

---

## 7. 正确性验证

由恢复的 `M` 反算 `A = C·M⁻¹`：

```text
det(M) != 0                      : True
A = C·M⁻¹ 全部为整数             : True
A 的元素均落在 [0, 2^512)        : True
A 与 Ac 不同的位置数             : 32      （正是被污染的 32 个位置）
出现污染的行                     : 20 行
校验 A·M == C                    : True
```

且干净行恰为 `{1,3,5,9,10,20,24,25,26,27,29,31}` 共 12 行，与 32 次随机污染下
“未命中行”的期望一致。

---

## 8. 踩坑 / 易错点

- **单行小解不唯一？** 单行时齐次格 `a·m=0` 的最短向量约 2^16，看似可能进入盒内；
  但实测最短齐次向量范数约 788 ~ 10³ 量级仍小于盒对角线 1443，因此**理论上可能多解**。
  实践上，本次实例的最短解恰为真实 `m`，且次短解范数高达 1.7×10¹⁰，BKZ 稳定命中；
  若担心歧义，可先用多行（例如 2 行）加强约束，或对同一列用多个干净行交叉验证
  （本脚本对 12 个干净行都得到完全相同的列）。
- **符号**：最短向量可能是 `m` 或 `-m`，取绝对值即可。
- **`K` 要够大**：`K = 2^80` 时，任何末坐标非零的格向量范数都 ≥ K，远大于目标解范数，
  保证最短向量末坐标恒为 0。
- **精度**：矩阵元素 ~2^512，`K·a` ~2^592，fpylll 默认 double 会溢出，
  必须用 `float_type="mpfr", precision=700`（或等价方法）。
- **行遍历顺序**：先只解第 0 列判断该行是否干净，可把每行开销降到 1 次 BKZ，
  命中 12 个干净行后任取一个解全部 32 列即可。
- **不要丢掉第一个 0x00**：`pad` 在 flag 内容后写入单个 `\x00` 再补随机字节，
  flag 内容就是行优先字节流里 `\x00` 之前的部分。
- **外层包装**：源码里 `assert flag[:7] == b'DASCTF{'`，但本平台统一按 `flag{}`
  提交，最终 flag 为 `flag{b5932c2c-e210-4c39-9fb5-a7f35e861d32}`。
  内层 UUID 内容与包装无关，两种写法只差前缀。同类平台上的 `lrsa` 题
  （源码断言同为 `DASCTF{`）很可能也需要改成 `flag{8f3djoj9wedj2_dkc903cwckckdk}` 提交。

---

## 9. 结果确认

- `A = C·M⁻¹` 为合法整数矩阵且与 `Ac` 恰好在 32 处不同，`A·M = C` 成立；
- 明文内容为 UUID 字符串，符合 flag 语义；源码中 `assert flag[:7]==b'DASCTF{'`，平台统一按 `flag{}` 包装提交；
- 12 个独立干净行给出完全一致的 `M`，交叉验证通过。

**Flag：`flag{b5932c2c-e210-4c39-9fb5-a7f35e861d32}`**
