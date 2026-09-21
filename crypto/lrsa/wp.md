# DASCTF Crypto - lrsa Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目名称 | lrsa |
| 来源 | DASCTF（附件 `CRYPTO附件/lrsa.zip`） |
| 类型 | Crypto / RSA + Lattice（二维格约化） |
| 附件 | `lrsa.zip`（`test.py` + `output.txt`） |
| lrsa.zip SHA256 | `864149048a25e9791b8fbaecff9a5371481258e65e5d9442a1badfae1d2b8923` |
| output.txt SHA256 | `7c97b2d1883419f7b2b61355cc57e3058c8601c494e04962b1d99adbeedfc14f` |
| Flag | `DASCTF{8f3djoj9wedj2_dkc903cwckckdk}` |

---

## 2. Recon

`test.py`：

```python
m = bytes_to_long(flag)

def getPQ(p, q):
    P = getPrime(2048)
    Q = getPrime(2048)
    t = (p * P - 58 * P + q) % Q
    return P, Q, t

B = getRandomNBitInteger(11)      # -> 1023
p = getPrime(B)
q = getPrime(B)
n = p * q
e = 65537
c = pow(m, e, n)
P, Q, t = getPQ(p, q)

print("B=", B)                     # 1023
print("P*P*Q=", P * P * Q)
print("P*Q*Q=", P * Q * Q)
print("t=", t)                     # 44
print("c=", c)
```

`output.txt` 给出 `B=1023`、`P^2*Q`、`P*Q^2`、`t=44`、`c`。注意**没有给出模数 `n = p*q`**。

规模：
- `p, q`：1023 bit 素数；
- `P, Q`：2048 bit 素数；
- `n = p*q`：约 2044~2046 bit。

---

## 3. 分析

### 3.1 从 `P^2 Q` / `P Q^2` 恢复 `P`、`Q`

```
gcd(P^2 Q, P Q^2) = P Q
P = (P^2 Q) / (P Q)
Q = (P Q^2) / (P Q)
```

因为 `P^2 Q` 与 `P Q^2` 仅有公因子 `P Q`，直接 `gcd` 即可得到 `P Q`，再相除得到 `P`、`Q`。验证：`P^2*Q == A`、`P*Q^2 == Bv`，且 `P`、`Q` 均为 2048 bit 素数。

### 3.2 核心关系

```text
t = (p*P - 58*P + q) mod Q
```

令 `x = p - 58`，则：

```text
x * P + q ≡ t   (mod Q)
=> x*P + q - t = k*Q
```

其中 `x = p-58 < 2^1023`，`q < 2^1023`，而 `Q ≈ 2^2048`。
这是一个**两个未知数都很小**的模线性方程。

几何意义：向量 `(x, q)` 满足 `xP + q ≡ t (mod Q)`。考察 2 维格

```text
L = { a*(P, 1) + b*(Q, 0) } = { (aP + bQ, a) }
```

取 `a = x, b = -k`，则格向量为

```text
(xP - kQ, x) = (t - q, x)
```

其第二坐标为 `x ≈ 2^1023`，第一坐标 `t - q ≈ -2^1023`，因此范数约为 `2^1024`，与格行列式
`det = |P*0 - 1*Q| = Q ≈ 2^2048` 的 2 维最短向量尺度 `sqrt(Q) ≈ 2^1024` 同阶——它正是格里的
一个**短向量**。于是对该格做 Gauss/LLL 约化，得到的短向量 `(u, x)` 中 `u = t - q`，从而：

```text
q = t - u,   p = x + 58,   n = p*q
```

解出 `p, q` 后就是普通 RSA 解密。

---

## 4. 为什么可行

- `gcd(P^2 Q, P Q^2) = P Q`：`P,Q` 为互异素数，指数分别是 (2,1) 与 (1,2)，逐素因子取 min 得 (1,1)。
- 格约化能命中的原因：目标向量 `(t-q, x)` 的两个坐标都 `< 2^1023`，与 `√det ≈ 2^1024` 同阶且更短，是格中（近似）最短向量；2 维时 Gauss 约化可精确求出最短向量，无需 LLL。
- 已知 `q < 2^1023`、`x < 2^1023`，盒体积 `2^2046 < Q ≈ 2^2048`，所以小解几乎唯一，约化结果可直接筛选。

反推得到的参数（十进制位数）：

```text
P, Q  : 2048 bit 素数
p     : 1023 bit 素数  (x = p-58 为 1023 bit)
q     : 1023 bit 素数
n     : 2046 bit
```

校验：`(p*P - 58*P + q) % Q == t == 44`，`pow(m, 65537, n) == c` 均成立。

---

## 5. 攻击链

```text
P^2*Q, P*Q^2
    |  gcd -> PQ, 相除
    v
P, Q (2048-bit)
    |
    |  x*P + q == t (mod Q),  x=p-58, q < 2^1023
    v
2-D 格 L = span{(P,1),(Q,0)}  --Gauss 约化-->  短向量 (t-q, x)
    |
    v
q = t - u,  p = x + 58,  n = p*q
    |
    |  RSA 解密 d = e^{-1} mod (p-1)(q-1)
    v
DASCTF{8f3djoj9wedj2_dkc903cwckckdk}
```

---

## 6. 完整脚本

见 `exploits/lrsa.py`：

```python
#!/usr/bin/env python3
import re, sys
from math import gcd
from Crypto.Util.number import isPrime, inverse, long_to_bytes

def gauss_reduce(b1, b2):
    while True:
        if b1[0]**2 + b1[1]**2 > b2[0]**2 + b2[1]**2:
            b1, b2 = b2, b1
        mu = round((b1[0]*b2[0] + b1[1]*b2[1]) / (b1[0]**2 + b1[1]**2))
        if mu == 0:
            break
        b2 = (b2[0] - mu*b1[0], b2[1] - mu*b1[1])
    return b1, b2

def solve(path):
    txt = open(path).read()
    val = lambda k: int(re.search(rf"{re.escape(k)}\s*=\s*(\d+)", txt).group(1))
    A, Bv, t, c = val("P*P*Q"), val("P*Q*Q"), val("t"), val("c")

    g = gcd(A, Bv)
    P, Q = A // g, Bv // g
    assert P*P*Q == A and P*Q*Q == Bv and isPrime(P) and isPrime(Q)

    b1, b2 = gauss_reduce((P, 1), (Q, 0))
    for base in (b1, b2):
        for sign in (1, -1):
            u, x = sign*base[0], sign*base[1]
            q = t - u
            if q <= 0 or x <= 0 or q.bit_length() > 1023 or x.bit_length() > 1023:
                continue
            p, n = x + 58, (x + 58) * q
            if isPrime(p) and isPrime(q) and (p*P - 58*P + q) % Q == t:
                d = inverse(65537, (p-1)*(q-1))
                return long_to_bytes(pow(c, d, n))
    raise RuntimeError("failed")

if __name__ == "__main__":
    print("FLAG:", solve(sys.argv[1] if len(sys.argv) > 1 else "output.txt").decode())
```

运行：

```bash
cd /Users/laiandi/ctf
.venv/bin/python exploits/lrsa.py work/lrsa/output.txt
```

---

## 7. 实际输出

```text
$ .venv/bin/python exploits/lrsa.py work/lrsa/output.txt
FLAG: DASCTF{8f3djoj9wedj2_dkc903cwckckdk}
```

额外校验输出：

```text
check relation OK, p,q prime OK
verify m^e==c: True
FLAG: DASCTF{8f3djoj9wedj2_dkc903cwckckdk}
```

---

## 8. 踩坑 / 易错点

- **题目没给 `n`**：不要急着找 `n`，先利用 `P^2 Q`/`P Q^2` 与 `t` 的关系恢复 `p, q`，再自己算 `n`。
- **`P`、`Q` 谁大谁小不定**：`gcd` 后再相除的顺序要对；`A//g` 是 `P`，`Bv//g` 是 `Q`（因为 `A = P^2 Q`，`Bv = P Q^2`）。
- **格基符号**：短向量可能是 `(t-q, x)` 也可能是其相反数 `(q-t, -x)`，枚举 `±` 两种符号即可。
- **小解筛选**：候选向量要满足 `x = p-58 > 0`、`q = t-u > 0`，且都 `< 2^1023`；再用 `(pP-58P+q) % Q == t` 与素数性做最终确认。
- **2 维无需 LLL**：Gauss（Lagrange）约化就能给出精确最短向量，实现简单，不必上 fpylll。
- **`t = 44` 非常小**：`t` 本身不提供额外信息，真正起作用的是“`x, q` 都小于 `√Q`”这一尺寸约束。

---

## 9. 结果验证

- `gcd(P^2 Q, P Q^2) = P Q`，恢复出的 `P`、`Q` 均为 2048 bit 素数，且 `P^2 Q`、`P Q^2` 与输入完全一致；
- 由短向量得到的 `p, q` 均为 1023 bit 素数，且满足 `t = (pP - 58P + q) mod Q`；
- 解密结果 `m` 满足 `m^65537 mod n == c`；
- 明文为可读的 `DASCTF{...}` 格式，与题目来源（DASCTF）一致。

**Flag：`DASCTF{8f3djoj9wedj2_dkc903cwckckdk}`**
