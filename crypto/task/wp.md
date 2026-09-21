# Quaternion DLP (task.py) WP

## 题目信息

- 附件：`task.py`
- 类型：crypto，四元数群上的离散对数
- 关键约束：`secret < 2 ** 50`
- Flag：`flag{ef9b2a64b3ead115a48ee0b842dc19ed}`

## 题目分析

题目在 `GF(p)` 上定义四元数（Hamilton 乘法），其中

```
p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
Q = Quaternion(123456789, 987654321, 135792468, 864297531)
R = power(Q, secret)
```

最后用 `key = md5(str(secret))` 做 AES-ECB 加密 flag。核心是已知 `Q` 和 `R = Q^secret`，求 `secret`。

把 `Q = a + t` 写成标量加纯虚部，其中 `t = b i + c j + d k`。由四元数乘法：

```
t^2 = -(b^2 + c^2 + d^2) = a^2 - N,   N = a^2 + b^2 + c^2 + d^2
```

于是 `t^2 = D`，且 `Q` 生成的子代数同构于 `GF(p)[x] / (x^2 - D)`。计算 Legendre 符号：

```
D = a^2 - N (mod p)
(D | p) = -1
```

即 `D` 是非二次剩余，故该二次代数同构于 `GF(p^2)`，其中 `Q` 对应 `λ = a + t`，`t^2 = D`。这样 `R = Q^secret` 就化成 `GF(p^2)` 中的离散对数。

取范数（共轭乘积）可把问题压回 `GF(p)`：把 `R` 表示为 `R = A·Q + B`，因为向量部分整体被 `A` 缩放，`A = R.b · b^{-1} mod p`，于是

```
μ = R.a + A·t  ∈ GF(p^2)
Norm(μ) = R.a^2 - A^2·D (mod p) = N^secret (mod p)
```

麻烦在于 `p - 1 = q · S`，其中 `q` 是 189 位大素数（这一支离散对数很难），而

```
S = 2 · 3 · 29 · 222587 · 1521613 · 4463413
```

是 68 位的光滑数。消掉大素数子群：令 `g = N^q`，则 `g` 的阶落在光滑的 `S` 内，实测

```
ord(g) = 131519555622217601661  (67 bits)
```

且目标满足 `h = Norm(μ)^q = g^secret`。因为 `ord(g) ≈ 2^67 > 2^50`，且题设 `secret < 2^50`，所以用 Pohlig–Hellman 在光滑阶上解出的唯一代表元就是 `secret` 本身。

对 `ord(g)` 分解得 `{3, 29, 1521613, 222587, 4463413}`，每个小素数子群用 BSGS 求解，再 CRT 合并，得到：

```
secret = 895942422329  (40 bits)
```

## 解题脚本

```python
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sympy, math
from sympy.ntheory.modular import crt

p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
a, b, c, d = 123456789, 987654321, 135792468, 864297531
Ra, Rb, Rc, Rd = (
    53580504271939954579696282638160058429308301927753139543147605882574336327145,
    79991318245209837622945719467562796951137605212294979976479199793453962090891,
    53126869889181040587037210462276116096032594677560145306269148156034757160128,
    97368024230306399859522783292246509699830254294649668434604971213496467857155,
)
ct = b'(\xe4IJ\xfd4%\xcf\xad\xb4\x7fi\xae\xdbZux6-\xf4\xd72\x14BB\x1e\xdc\xb7\xb7\xd1\xad#e@\x17\x1f\x12\xc4\xe5\xa6\x10\x91\x08\xd6\x87\x82H\x9e'

# Q = a + t, t^2 = D = a^2 - N
N = (a*a + b*b + c*c + d*d) % p
D = (a*a - N) % p
q = 440208639276132997491800604758226661590679912188273141493   # (p-1) 的大素因子

# R = A*Q + B  =>  mu = Ra + A*t
A = Rb * pow(b, -1, p) % p
norm_mu = (Ra*Ra - A*A*D) % p

# 消掉大素因子 q，落到光滑阶子群
g, h = pow(N, q, p), pow(norm_mu, q, p)
n = 131519555622217601661          # ord(g)，光滑
fac = sympy.factorint(n)
print("ord(g) factors:", fac)

def bsgs(base, target, order):
    m = math.isqrt(order) + 1
    table, e = {}, 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * base % p
    factor = pow(base, (-m) % order, p)
    gamma = target % p
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p

residues, mods = [], []
for r, k in fac.items():
    rk = r ** k
    residues.append(bsgs(pow(g, n // rk, p), pow(h, n // rk, p), rk) % rk)
    mods.append(rk)

x, M = crt(mods, residues)
secret = int(x) % int(M)
assert secret < 2 ** 50
print("secret =", secret)

# 验证 Q^secret == R
def qmul(Q1, Q2):
    a1, b1, c1, d1 = Q1
    a2, b2, c2, d2 = Q2
    return ((a1*a2 - b1*b2 - c1*c2 - d1*d2) % p,
            (a1*b2 + b1*a2 + c1*d2 - d1*c2) % p,
            (a1*c2 - b1*d2 + c1*a2 + d1*b2) % p,
            (a1*d2 + b1*c2 - c1*b2 + d1*a2) % p)

def qpow(Q, e):
    R = (1, 0, 0, 0)
    while e > 0:
        if e & 1:
            R = qmul(R, Q)
        Q = qmul(Q, Q)
        e >>= 1
    return R

assert qpow((a, b, c, d), secret) == (Ra, Rb, Rc, Rd)
print("verified Q^secret == R")

key = md5(str(secret).encode()).hexdigest().encode()
pt = AES.new(key=key, mode=AES.MODE_ECB).decrypt(ct)
print(unpad(pt, 16).decode())
```

运行结果：

```text
ord(g) factors: {3: 1, 29: 1, 1521613: 1, 222587: 1, 4463413: 1}
secret = 895942422329
verified Q^secret == R
flag{ef9b2a64b3ead115a48ee0b842dc19ed}
```

## Flag

```text
flag{ef9b2a64b3ead115a48ee0b842dc19ed}
```

## 总结

四元数乘法的关键是它满足二次特征方程，`Q` 生成的子代数（`1, Q`）同构于 `GF(p)[x]/(x^2 - (a^2 - N))`。由于判别式 `a^2 - N` 是非二次剩余，该代数分裂为 `GF(p^2)`，原问题化为有限域上的 DLP。再用范数把元素映回 `GF(p)*`，并利用 `p - 1` 中「一个 189 位大素数 × 68 位光滑数」的结构，把大素数子群消掉，剩下的光滑阶远大于 `2^50`，因此 Pohlig–Hellman 解出的商恰好就是题目限制下的 `secret`。
