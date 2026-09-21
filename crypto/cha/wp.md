# crypto cha.py WP

## 题目信息

- 附件：`cha.py`
- 类型：线性递推（三阶常系数）+ 大数/矩阵快速幂 + AES-ECB
- Flag：`flag{519427b3-d104-4c34-a29d-5a7c128031ff}`

## 题目分析

```python
from secret import flag
from hashlib import md5, sha256
from Crypto.Cipher import AES

cof_t = [[353, -1162, 32767], [206, -8021, 42110], ...]   # 100 组三元组

def cal(i, cof):
    if i < 3:
        return i + 1                       # cal(0)=1, cal(1)=2, cal(2)=3
    else:
        return cof[2]*cal(i-3, cof) + cof[1]*cal(i-2, cof) + cof[0]*cal(i-1, cof)

s = 0
for i in range(100):
    s += cal(200000, cof_t[i])

s = str(s)[-2000:-1000]
key = md5(s).hexdigest().decode('hex')     # key = 16 字节 md5 原始摘要
check = sha256(key).hexdigest()
verify = '2cf44ec396e3bb9ed0f2f3bdbe4fab6325ae9d9ec3107881308156069452a6d5'
assert check == verify
aes = AES.new(key, AES.MODE_ECB)
data = flag + (16 - len(flag) % 16) * "\x00"
print(aes.encrypt(data).encode('hex'))
# 4f12b3a3eadc4146386f4732266f02bd03114a404ba4cb2dabae213ecec451c9d52c70dc3d25154b5af8a304afafed87
```

`cal` 是三阶常系数线性递推：

```
cal(i) = c0·cal(i-1) + c1·cal(i-2) + c2·cal(i-3)
c0,c1,c2 = cof[0], cof[1], cof[2]
初始: cal(0)=1, cal(1)=2, cal(2)=3
```

需要 100 组系数下的 `cal(200000)`，再求和、取十进制串的 `[-2000:-1000]`，
用其 MD5 作为 AES 密钥解密。

## 关键点：只需要最后 2000 位

直接求 `cal(200000)` 的真值会有约 `200000·log10(c0) ≈ 60 万位十进制`
（`c0` 最大 998），100 组更是慢得离谱。

但注意 `str(s)[-2000:-1000]` 完全落在最后 2000 位里，因此它只取决于

```
R = s mod 10^2000
sub = ("%02000d" % R)[:1000]      # 等价于 str(s)[-2000:-1000]
```

（`s` 位数远大于 2000，前导零补到 2000 位后取前 1000 位即可。）

于是整个递推可以在 **模 `10^2000`** 下用矩阵快速幂计算，规模只有 2000 位十进制，
纯 Python 也能瞬间跑完：

```
[ cal(n)   ]   [ c0 c1 c2 ]^(n-2)   [ cal(2)=3 ]
[ cal(n-1) ] = [ 1  0  0  ]       · [ cal(1)=2 ]
[ cal(n-2) ]   [ 0  1  0  ]         [ cal(0)=1 ]
```

最后用题目自带的 `sha256(key) == verify` 校验推导是否正确。

## 攻击链

```
线性递推 -> 矩阵快速幂（模 10^2000）
        -> R = Σ cal(200000, cof_t[i]) mod 10^2000
        -> sub = ("%02000d" % R)[:1000]
        -> key = md5(sub).digest()
        -> sha256(key) == verify  (校验通过)
        -> AES-ECB 解密 -> flag
```

## Exploit

见 `exploits/cha_solve.py`。核心代码：

```python
import ast, hashlib
from Crypto.Cipher import AES

MOD = 10**2000
cof = ast.literal_eval(...)                 # cof_t

def matmul(A, B):
    return [[sum(A[i][k]*B[k][j] for k in range(3)) % MOD for j in range(3)]
            for i in range(3)]

def matpow(A, e):
    R = [[1,0,0],[0,1,0],[0,0,1]]
    while e:
        if e & 1: R = matmul(R, A)
        A = matmul(A, A); e >>= 1
    return R

def cal(n, c0, c1, c2):
    if n < 3: return n + 1
    P = matpow([[c0%MOD, c1%MOD, c2%MOD],[1,0,0],[0,1,0]], n-2)
    return sum(P[0][j]*v for j, v in enumerate((3,2,1))) % MOD

s = 0
for c0, c1, c2 in cof:
    s = (s + cal(200000, c0, c1, c2)) % MOD

sub = ('%02000d' % s)[:1000]               # == str(s)[-2000:-1000]
key = hashlib.md5(sub.encode()).digest()
assert hashlib.sha256(key).hexdigest() == verify
pt = AES.new(key, AES.MODE_ECB).decrypt(CT)
print(pt.rstrip(b'\x00').decode())
```

## 运行结果

```
check match: True
plaintext: b'flag{519427b3-d104-4c34-a29d-5a7c128031ff}\x00\x00\x00\x00\x00\x00'
```
