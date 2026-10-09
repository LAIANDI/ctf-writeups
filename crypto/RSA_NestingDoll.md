# CCB CISCN 2025 Quals - RSA_NestingDoll Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目名称 | RSA_NestingDoll |
| 来源 | CCB CISCN 2025 Quals（分类 `crypto`，无远程环境） |
| 类型 | Crypto / RSA（Euler φ 泄漏，multiprime RSA） |
| 附件 | `src.py`、`output.txt` |
| src.py SHA256 | `11e794f9799b086bebdf3f4354488e733d678ac01e42a4f3cf9febd660a85af4` |
| output.txt SHA256 | `100aafdf5fb96eb3701a9281502a2f5f71bba59fc7a8daf09ad87f68b4c21756` |
| 环境 | Python 3 + `pycryptodome`、`sympy`、`tqdm` |
| Flag | `flag{fak3_r5a_0f_euler_ph1_of_RSA_040a2d35}` |

---

## 2. Recon

`src.py`：

```python
flag = open("./flag.txt","rb").read()
flag = bytes_to_long(flag + os.urandom(2048//8 - len(flag)))
e = 65537

def get_smooth_prime(bits, smoothness, max_prime=None):
    assert bits - 2*smoothness > 0
    p = 2
    if max_prime is not None:
        assert max_prime > smoothness
        p *= max_prime
    while p.bit_length() < bits - 2*smoothness:      # 984
        factor = getPrime(smoothness)                # 20-bit 素数
        p *= factor
    bitcnt = (bits - p.bit_length()) // 2            # ~10..20
    while True:
        prime1 = getPrime(bitcnt); prime2 = getPrime(bitcnt)
        tmpp = p * prime1 * prime2
        if tmpp.bit_length() != bits: 调整 bitcnt; continue
        if isPrime(tmpp + 1):
            p = tmpp + 1; break
    return p

p1,q1,r1,s1 = getPrime(512) x4
n1 = p1*q1*r1*s1                       # inner RSA, 2048 bit
p = get_smooth_prime(1024, 20, p1)     # outer prime, 1024 bit
q = get_smooth_prime(1024, 20, q1)
r = get_smooth_prime(1024, 20, r1)
s = get_smooth_prime(1024, 20, s1)
n = p*q*r*s                            # outer RSA, 4096 bit
print(n1); print(n); print(pow(flag, e, n1))
```

`output.txt` 给出三个数：`inner RSA modulus = n1`（2047 bit）、`outer RSA modulus = n`（4095 bit）、`Ciphertext = c`（2043 bit）。明文是 `flag` 补到 2048 bit（256 字节）后取整数。

---

## 3. 分析

### 3.1 结构：内外两层 RSA 的“套娃”

外层每个素数都由一个内层素数“生长”而来：

```
p = 1 + p1 * S_p        S_p 是 < 2^20-smooth 的数
q = 1 + q1 * S_q
r = 1 + r1 * S_r
s = 1 + s1 * S_s
```

其中 `p1,q1,r1,s1` 恰好是内层模数 `n1 = p1*q1*r1*s1` 的四个 512-bit 素因子。
`S_p` 的构成：`2 * (若干 20-bit 素数) * prime1 * prime2`，最大素因子 `< 2^20`，所以 `S_p` 是 **B-smooth（B = 2^20）**。

关键观察：

```
p - 1 = p1 * S_p
```

- `p1 | n1`（n1 已知）
- `S_p | K`，其中 `K = lcm(1, 2, ..., 2^20)`

因此 `(p-1) | n1 * K`，对四个外层素数都成立。于是

```
M = n1 * K   是  λ(n) = lcm(p-1, q-1, r-1, s-1)  的倍数
```

### 3.2 有了 λ(n) 的倍数 ⇒ 分解 n

这是经典结论：已知 `n` 和 `λ(n)` 的任意倍数 `M`，即可分解 `n`。把 `M = 2^s · d`（d 为奇数），对随机 `a` 计算 `x = a^d mod n`，再反复平方；一旦出现
`x ≠ ±1` 但 `x² ≡ 1 (mod n)`，则 `gcd(x-1, n)` 给出非平凡因子（Miller–Rabin 平方根法）。

对 4 素数模数，随机底失败概率约 `2^{-(k-1)}`，一两次即可。实测本机一次大指数幂约 90 秒（`M` 约 1.5 Mbit），整体分解约 250 秒。

### 3.3 从外层素数还原内层素数

分解得到 `p,q,r,s` 后：

```
p1 = (p-1) / S_p = (p-1) 去掉所有 < 2^20 的素因子
```

即对 `p-1` 用 `< 2^20` 的素数做试除，剩下的 512-bit 数就是 `p1`。四个合起来正好是 `n1`。随后

```
φ(n1) = (p1-1)(q1-1)(r1-1)(s1-1)
d = e^{-1} mod φ(n1)
flag = c^d mod n1
```

---

## 4. Why it works（关键中间量）

- `B = 2^20 = 1048576`，`< B` 的素数共 `82025` 个。
- `K = lcm(1..B)`，约 `1512566` bit；`v2(K) = 20`。
- `M = n1 * K` 约 `1514613` bit；`M` 是 `λ(n)` 的倍数（实测 `pow(a, M, n) == 1`）。
- 奇部 `d = M >> 20`。
- 内层四个素数均为 512-bit，乘积校验 `== n1`。
- `e = 65537`。

---

## 5. Attack chain

```
src.py 给出 n1（内层模数, 未知分解）
        │
        ├─ 内层素数 p1..s1 被当成外层素数的 max_prime
        │        => (p-1) = (inner_i) · (2^20-smooth)
        │
        ├─ M = n1 · lcm(1..2^20) 是 λ(n) 的倍数
        │
        ├─ Miller–Rabin 平方根法  ──► 分解外层 n = p·q·r·s
        │
        ├─ 对每个 (p-1) 试除所有 <2^20 素数 ──► 恢复内层 p1,q1,r1,s1
        │
        └─ φ(n1) → d = e^{-1} mod φ → m = c^d mod n1 → 去填充 → flag
```

---

## 6. Full script

`exploits/crypto/RSA_NestingDoll.py`：

```python
#!/usr/bin/env python3
import re, math, random, time
from math import gcd
from sympy import isprime

OUTPUT = ".../RSA_NestingDoll/output.txt"
B = 1 << 20
E = 65537

def load(path):
    txt = open(path).read()
    n1 = int(re.search(r"inner RSA modulus = (\d+)", txt).group(1))
    n  = int(re.search(r"outer RSA modulus = (\d+)", txt).group(1))
    c  = int(re.search(r"Ciphertext = (\d+)", txt).group(1))
    return n1, n, c

def small_primes(bound):
    s = bytearray([1]) * (bound + 1); s[0] = s[1] = 0
    for i in range(2, int(bound ** 0.5) + 1):
        if s[i]:
            s[i * i::i] = bytearray(len(s[i * i::i]))
    return [i for i in range(2, bound + 1) if s[i]]

def split(m, d, s):
    while True:
        a = random.randrange(2, m - 1)
        g = gcd(a, m)
        if 1 < g < m: return g
        x = pow(a, d, m)
        if x in (1, m - 1): continue
        for _ in range(s - 1):
            y = pow(x, 2, m)
            if y == 1:
                g = gcd(x - 1, m)
                if 1 < g < m: return g
                break
            if y == m - 1: break
            x = y

def factor(m, d, s, out):
    if m == 1: return
    if isprime(m): out.append(m); return
    f = split(m, d, s); factor(f, d, s, out); factor(m // f, d, s, out)

def main():
    n1, n, c = load(OUTPUT)
    primes = small_primes(B)
    K = 1
    for q in primes:
        K *= q ** int(math.log(B) / math.log(q))    # K = lcm(1..2^20)
    M = n1 * K
    d, s = M, 0
    while d % 2 == 0: d //= 2; s += 1
    outer = []; factor(n, d, s, outer); outer = sorted(outer)
    assert math.prod(outer) == n
    inner = []
    for p in outer:
        x = p - 1
        for q in primes:
            while x % q == 0: x //= q
        inner.append(x)
    inner = sorted(inner)
    assert math.prod(inner) == n1 and all(isprime(x) for x in inner)
    phi = 1
    for x in inner: phi *= x - 1
    flag_int = pow(c, pow(E, -1, phi), n1)
    print(flag_int.to_bytes((flag_int.bit_length()+7)//8, "big").split(b"}")[0] + b"}")

main()
```

运行（约 4 分钟，瓶颈是 1.5 Mbit 指数的大数幂）：

```bash
.venv/bin/python exploits/crypto/RSA_NestingDoll.py
```

---

## 7. Observed output

```
M bits 1514613 v2 20
outer factors found in 249.6645848751068 s
check product==n: True
inner bits: [512, 512, 512, 512]
inner product==n1: True
all prime: True
FLAG bytes: b'flag{fak3_r5a_0f_euler_ph1_of_RSA_040a2d35}\x7fp\xcb...'
```

（`\x7f\xcb...` 是 `os.urandom` 的填充字节。）

---

## 8. Gotchas / dead ends

- **不要试图直接分解 `n1`**：四个随机 512-bit 素数，ECM/GNFS 都不可行；也没有小因子（`gcd(n1,n)==1`，`Pollard p-1` 无效）。
- `gcd(n1, n)`、`gcd(n1, n-1)` 均为 1，没有共享素数。
- 注意 `p-1` 的大素因子是 512-bit，**Pollard `p-1` stage 1/2 也不行**——`S_p` smooth 而 `p1` 不 smooth。
- `K` 必须覆盖 `S_p` 的全部素因子，包括可能出现的小素数（`prime1/prime2` 的 bit 数最小可到 ~10），所以取 `lcm(1..2^20)` 而不是只取 `[2^19,2^20)` 的素数。
- `M` 巨大（~1.5 Mbit），每次 `pow(a, d, n)` 约 90 秒；随机底失败时需重试，整体 250 秒左右，属正常。

---

## 9. Verification

- 分解完整性：`math.prod(outer) == n`。
- 内层正确性：四个 512-bit 数均为素数且 `prod == n1`。
- 明文可读且符合 flag 格式：`flag{fak3_r5a_0f_euler_ph1_of_RSA_040a2d35}`，其长度 < 256 字节，尾部为随机填充，与 `src.py` 的补位逻辑一致。
