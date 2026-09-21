# 2022 网鼎杯 青龙组 Reverse-1（Re2.exe）Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目名称 | Re2.exe（2022 第二届网鼎杯 青龙组 逆向签到第一题） |
| 类型 | Reverse |
| 附件 | `challenges/Re2.exe` |
| SHA256 | `313a5dddca33d69a48acc41dfcb491c6a1f8d73fb714c117608dddd43249f690` |
| 架构/环境 | PE32+ (x86-64, Windows, VS Debug 编译，PDB: `wdbRe2.pdb`) |
| 加壳 | UPX（段名被改成 `FUK0`/`FUK1`） |
| 运行方式 | Windows / Wine / x64dbg；本题也通过 Unicorn 静态脱壳求解 |
| Flag | `flag{why_m0dify_pUx_SheLL}` |

---

## 2. Recon

```bash
$ file Re2.exe
Re2.exe: PE32+ executable (console) x86-64, for MS Windows

$ strings -n 6 Re2.exe
...
<<Input your flag: 
Wrong.
Right!
...
InitializeSListHead
IsDebuggerPresent
RaiseException
...
```

PE 结构很反常：

```text
Sections:
  0 FUK0   VA 0x140001000  VirtualSize 0x23000  RawSize 0     (未初始化/BSS)
  1 FUK1   VA 0x140024000  VirtualSize 0x04000  RawSize 0x3800 (压缩数据)
  2 .rsrc  VA 0x140028000  ...
EntryPoint = 0x1400274e0  (位于 FUK1)
```

段名 `FUK0` / `FUK1` 是作者把 UPX 的 `UPX0` / `UPX1` 改名的结果，用来让
`upx -d` 自动检测失败。入口点是一段**自解压 stub**：开头就是典型的按位读取
（`add ebx,ebx` + 紧跟 `repz ret` 垃圾字节）的解压器循环，源指针指向 FUK1，
目的指针指向 FUK0：

```asm
1400274e0  push rbx / rsi / rdi / rbp
1400274e4  lea rsi, [rip - 0x34eb]       ; rsi = 0x140024000 (FUK1, 压缩源)
1400274eb  lea rdi, [rsi - 0x23000]      ; rdi = 0x140001000 (FUK0, 解压目标)
1400274f2  push rdi
...
1400275d6  pop rsi                        ; 解压结束，之后是导入表重建 + 重定位 + jmp 到真实代码
```

解压器本身不需要任何导入，完全自包含，因此可以用 Unicorn 直接模拟到
`0x1400275d6`，把 `0x140001000` 起始的解压结果 dump 出来。

---

## 3. 脱壳（Unicorn 静态模拟）

关键地址与常量：

| 名称 | 值 |
| --- | --- |
| 镜像基址 | `0x140000000` |
| 入口点 | `0x1400274e0` |
| 解压源 FUK1 | `0x140024000` |
| 解压目标 FUK0 | `0x140001000` |
| 解压结束点 | `0x1400275d6` (`pop rsi`) |
| 解压产物大小 | `0x25836` 字节 |

解压后 dump 里能看到真实字符串与数据：

```text
0x19d90  "<<Input your flag: "
0x19f28  "Wrong."
0x19f70  "Right!"
0x1acbc  "C:\\Users\\admin\\source\\repos\\wdbRe2\\x64\\Debug\\wdbRe2.pdb"
0x2501e  "IsDebuggerPresent"
...
```

在镜像 `0x140001000` 基址下，`main` 位于 `0x140011c70`（真实代码在解压产物中
偏移 `0x10c70`）。

---

## 4. 算法分析

### 4.1 主流程（`0x140011c70`，即 `main`）

```asm
140011cab  lea rcx, [0x14001ad90]      ; "<<Input your flag: "
140011cb2  call printf
140011cbb  lea rcx, [0x14001af68]      ; "%200s"
140011cc2  call scanf
140011cc7  lea rcx, [rbp+0x10]         ; 输入缓冲区
140011ccb  call 0x140011235            ; 第一道校验（见 4.2）
140011cd0  test eax, eax
140011cd2  jne  0x140011ce8            ; 长度不是 20 -> 打印 Wrong 退出
...
140011d0a  mov edx, 0x14               ; 20
140011d0f  lea rcx, [rbp+0x10]
140011d13  call 0x1400111e5            ; 第二道校验（见 4.3），失败则 longjmp(1)->Wrong
```

这里用 `setjmp` / `longjmp`（导入 `__intrinsic_setjmp` / `longjmp`）来做控制流：
第一道校验失败 `longjmp(ctx, 非20)`，成功 `longjmp(ctx, 20)`；第二道校验
逐字符比较失败 `longjmp(ctx, 1)`，全部通过 `longjmp(ctx, 2)`，`setjmp`
返回值驱动打印 `Wrong.` / `Right!`。

### 4.2 第一道校验（`0x140011840`）

```asm
140011876  mov  rcx, [rbp+0x100]       ; 输入
14001187d  call strlen                 ; 0x140011037 -> IAT strlen
140011882  mov  [rbp+4], eax
140011885  cmp  [rbp+4], 0x14          ; 长度必须 == 20
140011889  je   0x14001189c
14001188b  ...                         ; 否则 longjmp(ctx, 长度) -> Wrong
14001189c  mov  [rbp+4], 0
1400118a5  inc  [rbp+4]
1400118ad  cmp  [rbp+4], 0x24          ; i < 36
1400118be  movsx eax, byte [rcx+rax]   ; c = input[i]
1400118c2  xor  eax, 0x66              ; c ^= 0x66
1400118d0  mov  [rdx+rcx], al          ; 写回 input[i]
1400118d5  mov edx, 0x14               ; longjmp(ctx, 20)
```

即：**长度必须为 20**，然后对输入前 36 字节做 `input[i] ^= 0x66`。

### 4.3 第二道校验（`0x1400119b0`，被 `sub_1400111E5` 调用）

```asm
1400119f4  ; for (i = 0; i < len(=20); i++)
140011a0c  mov  rax, [rbp+8]           ; i
140011a10  mov  rcx, [rbp+0x100]       ; input
140011a1d  movsx eax, byte [rax+rcx]   ; c = input[i]
140011a20  add  eax, 0x0a              ; c += 10
140011a23  xor  eax, 0x50              ; c ^= 0x50
140011a26  mov  edx, eax
140011a2b  call 0x140011276            ; -> 0x140011920 比较函数
```

比较函数（`0x140011920`）：

```asm
140011958  movsxd rax, [rbp+0xe0]      ; i
14001195f  lea    rcx, [0x14001d000]   ; 目标表
140011966  mov    edx, [rbp+0xe8]      ; 变换后的字符
14001196c  cmp    dword [rcx+rax*4], edx
14001196f  je     0x140011982          ; 相等 -> 继续
140011971  mov    edx, 1
14001197d  call   longjmp              ; 不等 -> longjmp(ctx, 1) -> Wrong
```

全 20 个字符都匹配后，走到 `0x140011a32` 执行 `longjmp(ctx, 2)` -> `Right!`。

### 4.4 目标表（`0x14001d000`，20 个 dword）

```text
0x4B 0x48 0x79 0x13 0x45 0x30 0x5C 0x49 0x5A 0x79
0x13 0x70 0x6D 0x78 0x13 0x6F 0x48 0x5D 0x64 0x64
```

---

## 5. 为什么可以反推

对每个字符 `c`，最终比较的等式是：

```text
((c ^ 0x66) + 0x0a) ^ 0x50 == table[i]
```

每一步都是可逆的（`+` 在 8 位下对 256 取模，`^` 自逆），于是：

```text
flag[i] = ((table[i] ^ 0x50) - 0x0a) ^ 0x66
```

代入表：

```python
a = [0x4B,0x48,0x79,0x13,0x45,0x30,0x5C,0x49,0x5A,0x79,
     0x13,0x70,0x6D,0x78,0x13,0x6F,0x48,0x5D,0x64,0x64]
flag = ''.join(chr(((b ^ 0x50) - 0x0a) ^ 0x66) for b in a)
# -> "why_m0dify_pUx_SheLL"
```

（`0x66` 来自第一道校验写回输入的那一步，很多 writeup 把它漏掉会得到乱码，
务必先做 `^0x66` 再做 `+A ^50`，逆向时顺序相反。）

---

## 6. 攻击链（解题链）

```text
Re2.exe (UPX, FUK0/FUK1)
      |
      |  改回 UPX0/UPX1 + upx -d    —— 或 ——
      |  Unicorn 模拟 stub: EP(0x1400274e0) -> 0x1400275d6，dump 0x140001000
      v
真实 payload (base 0x140001000)
      |
      |  读取 main 0x140011c70 / 校验函数 0x140011840, 0x1400119b0
      v
等式: ((input[i] ^ 0x66) + 0x0a) ^ 0x50 == table[i], len==20
      |
      |  input[i] = ((table[i] ^ 0x50) - 0x0a) ^ 0x66
      v
flag{why_m0dify_pUx_SheLL}
```

---

## 7. 完整脚本

见 `exploits/Re2.py`（自包含，Unicorn 静态脱壳 + 逆运算）：

```python
#!/usr/bin/env python3
import struct, sys
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RSP

BASE = 0x140000000
PAYLOAD_OFF_TABLE = 0x1C000  # VA 0x14001d000 - payload base 0x140001000

def unpack(path):
    pe = pefile.PE(path)
    raw = open(path, "rb").read()
    img = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
    img[:pe.OPTIONAL_HEADER.SizeOfHeaders] = raw[:pe.OPTIONAL_HEADER.SizeOfHeaders]
    for s in pe.sections:
        if s.SizeOfRawData:
            img[s.VirtualAddress:s.VirtualAddress+s.SizeOfRawData] = \
                raw[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(BASE, 0x100000); mu.mem_write(BASE, bytes(img))
    mu.mem_map(0x200000000, 0x200000); mu.reg_write(UC_X86_REG_RSP, 0x200100000)
    END = 0x1400275D6  # pop rsi = depacker done
    mu.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: uc.emu_stop() if a == END else None)
    mu.emu_start(BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint, END, count=20_000_000)
    return bytes(mu.mem_read(0x140001000, 0x26000))

def solve(path):
    payload = unpack(path)
    table = list(struct.unpack_from("<20I", payload, PAYLOAD_OFF_TABLE))
    return "".join(chr(((t ^ 0x50) - 0x0A) ^ 0x66) for t in table)

if __name__ == "__main__":
    exe = sys.argv[1] if len(sys.argv) > 1 else "challenges/Re2.exe"
    body = solve(exe)
    print(f"flag   : flag{{{body}}}")
```

运行：

```bash
cd /Users/laiandi/ctf
.venv/bin/python exploits/Re2.py challenges/Re2.exe
```

---

## 8. 实际输出

```text
$ .venv/bin/python exploits/Re2.py challenges/Re2.exe
length : 20
flag   : flag{why_m0dify_pUx_SheLL}
```

---

## 9. 踩坑 / 易错点

- **段名伪装成 `FUK0`/`FUK1`**：直接 `upx -d` 会报错。可 010 Editor 改回
  `UPX0`/`UPX1` 再脱壳，或用本题的 Unicorn 方案（注意解压器自包含，不需要
  处理导入表）。
- **两次变换的顺序**：第一道校验对输入前 36 字节 `^0x66`，第二道才 `+0x0a`
  再 `^0x50`。逆向顺序为 `((t^0x50)-0x0a)^0x66`。只用 `((t^0x50)-0x0a)`
  会得到不可打印字节。
- **长度常量容易看错**：长度判断是 `cmp [rbp+4], 0x14`（20），异或循环上界是
  `0x24`（36，故意越界异或，属 VS `/RTC` 残留），别把 36 当成 flag 长度。
- **部分网络 writeup 的表里多写了一个 `0x18`**，多算出一个 `X`。以二进制里
  `0x14001d000` 的 20 个 dword 为准，flag 恰好 20 字符。
- **`setjmp`/`longjmp` 控制流**：`Wrong`/`Right` 不是直接顺序打印，而是通过
  `longjmp` 传 1/2 回到 `setjmp` 决定分支，静态阅读时不要被绕晕。

---

## 10. 结果验证

- 长度 20，与第一道校验完全一致；
- 反推结果 `why_m0dify_pUx_SheLL` 为可读英文短句（"why modify UPX shell"），
  符合出题人意图；
- 与 51CTO / FreeBuf / 博客园三篇网鼎杯官方题解给出的
  `flag{why_m0dify_pUx_SheLL}` 一致。

**Flag：`flag{why_m0dify_pUx_SheLL}`**
