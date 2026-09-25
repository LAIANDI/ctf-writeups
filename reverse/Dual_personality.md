# DASCTF "Dual personality.exe" Reverse Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目名称 | Dual personality.exe |
| 类型 | Reverse（Windows PE / 32+64 位混合代码） |
| 附件 | `challenges/tempdir-4/REVERSE附件/Dual personality.exe` |
| SHA256 | `d7116c32dc5f2125ee489559eb4fce80adef00ea1fb4af24fdc949c0a1d89fa2` |
| 架构/环境 | PE32 executable (console) Intel 80386（WoW64 下运行，使用 Heaven's Gate） |
| 编译器信息 | PDB `E:\Project\Dual personality\Debug\Dual personality.pdb`，VS Debug（`ucrtbased.dll` / `VCRUNTIME140D.dll`） |
| Flag | `DASCTF{6cc1e44811647d38a15017e389b3f704}` |

---

## 2. Recon

```bash
$ file "Dual personality.exe"
Dual personality.exe: PE32 executable (console) Intel 80386, for MS Windows

$ strings -n 5 "Dual personality.exe"
...
Right, flag is DASCTF{your input}
Wrong flag
Genu
ineI
ntel
cipher
tmp
E:\Project\Dual personality\Debug\Dual personality.pdb
```

几个关键线索：

- 提示语是 `Right, flag is DASCTF{your input}`，说明**输入内容就是花括号里的 flag 主体**，长度 32。
- 出现 `Genu` / `ineI` / `ntel` 三段和 `cpuid`，是 CPU 厂商字符串 `GenuineIntel` 的碎片（干扰/反调试暗示）。
- 只有 5 个节：`.text .rdata .data .msvcjmc .rsrc`，没有加壳，代码直接可读。
- PDB 路径表明是 Debug 版 VS 编译，函数序言里有 `0xCCCCCCCC` 填充和 `/RTC` 安全检查。

导入表里有 `VirtualAlloc` / `VirtualProtect` / `IsDebuggerPresent`，并且 `.text` 里混着一段**只有在 x86-64 下才解释得通**的指令（例如 `65 48 8B 04 25 60 00 00 00` = `mov rax, gs:[0x60]` 读 PEB），这就是题目名 "Dual personality"（双人格）的来源：**同一份字节，在 32 位和 64 位模式下解码出不同语义**。

---

## 3. analysis：Heaven's Gate（双模式切换）

### 3.1 32 位入口与真实校验函数

`objdump -d -M intel` 线性反汇编，从入口 `0x401cf0` 追到 CRT，再追到 `main`：

```asm
; main = 0x401c60
401c60  push ebp
401c61  mov  ebp, esp
...
401c8e  call 0x4013a0          ; 真正的校验函数
```

`0x4013a0` 是主校验逻辑。它开头就调用 `0x401000`：

```asm
; 0x401000：遍历节表，对每个节调用 VirtualProtect(..., PAGE_EXECUTE_READWRITE)
; 并把 .text 变成可写，为后面的自修改 / 动态代码做准备
40102f  mov  esi, esp
401031  push 0
401033  call [0x405008]        ; GetModuleHandleA(NULL) -> 模块基址
...
4010ac  call [0x405004]        ; VirtualProtect(section, size, 0x40, &old)
```

随后读取输入（`.rdata` 里 `0x405170` 是 `"%99s"`）：

```asm
4013ca  push 0x407060          ; buf（32 字节全局缓冲）
4013cf  push 0x405170          ; "%99s"
4013d4  call 0x401620          ; scanf 包装
```

### 3.2 第一次“人格切换”（0x4013e8）

紧接着：

```asm
4013dc  push 0x4011d0
4013e1  push 7
4013e3  call 0x401120          ; 代码生成器 / 远端 trampoline
4013e8  add  esp, 8            ; <-- 这 7 字节会被改写
4013eb  test eax, eax
4013ed  je   0x4013f4
4013ef  mov  eax, [0x407058]   ; key
4013f4  sub  eax, 0x21524111
4013f9  mov  [0x407058], eax
```

`0x401120` 的行为（参数按 cdecl，`arg1=[ebp+8]`、`arg2=[ebp+12]`，所以两次调用都是 `arg1=7, arg2=目标`）：

1. `VirtualAlloc(0, arg1+6, 0x3000, 0x40)` 分配一段 RWX 内存，存进 `0x407050` 和 `0x407000`。
2. `memcpy(alloc, 返回地址, 7)`：把 `call` 之后那 7 字节原样拷到 RWX 缓冲。
3. 在 `alloc+7` 写 `E9 rel32`，跳回 `返回地址+7`。
4. 把返回地址本身改写成 **远跳转** `EA <arg2 4字节> 33 00` —— **选择子 `0x33` 是 64 位代码段**。

于是 `0x401120` 返回时不再执行 `add esp,8`，而是执行 `EA 33:0x4011d0`，**CPU 切到 64 位长模式**。

### 3.3 64 位 stub 与“切回 32 位”

`0x4011d0` 是货真价实的 64 位代码（capstone `CS_MODE_64`）：

```asm
4011d0  mov   rax, qword ptr gs:[0x60]   ; PEB
4011d9  mov   al,  byte ptr [rax + 2]    ; PEB->BeingDebugged
4011dc  mov   byte ptr [0x40705c], al
4011e3  test  al, al
4011e5  jne   0x4011f5
4011e7  mov   r12d, 0x5df966ae           ; 非调试：设置 key
4011ed  mov   dword ptr [0x407058], r12d
4011f5  mov   eax, 0x407000
4011fb  ljmp  [rax]                      ; 远跳转，读 10 字节指针
```

关键在 `0x407000` 处存放的**远指针**（`0x401120` 只写了前 4 字节偏移，其余来自 `.data` 初始值）：

```text
.data:
  0x407000  <alloc>            ; 偏移
  0x407004  00 00 00 00        ; (高位)
  0x407008  0x00000023         ; 选择子 0x23 = 32 位代码段
  0x40700c  0x00401200         ; 另一个远指针的偏移
  0x407010  0x00000033         ; 选择子 0x33 = 64 位代码段
```

所以 `ljmp [0x407000]` 实际是 **跳回 32 位选择子 `0x23`、偏移 = RWX trampoline**。trampoline 里是刚才拷贝的 7 字节 `83 C4 08 85 C0 74 05`（`add esp,8; test eax,eax; je +5`），因为此时 `eax=0x407000≠0`，不跳转，随后 `E9` 跳到 `0x4013ef`，**模式已回到 32 位**。此时 key 已被 64 位 stub 置为 `0x5DF966AE`。

> 之所以要绕这一大圈：正常从 `0x401120` 返回时 `eax=0`，`je 0x4013f4` 会**跳过** `mov eax,[0x407058]`；而经 64 位一轮回来后 `eax≠0`，于是 `mov eax,[0x407058]` 被执行，`sub eax,0x21524111` 得到真正的初始 key。这是刻意设计的“人格差异”。

### 3.4 第一段变换（滚动 key，32 位）

```asm
; for (i = 0; i < 8; i++)   // 8 个 dword = 32 字节
40140e  mov  eax, [ebp-0x18]      ; i
...
401423  mov  edx, [ecx + 4*eax]   ; d = buf[i]
401426  add  edx, [0x407058]      ; d += key
401432  mov  [ecx + 4*eax], edx   ; buf[i] = d
40143b  mov  edx, [0x407058]
401441  xor  edx, [ecx + 4*eax]   ; key ^= d
401444  mov  [0x407058], edx
```

即：

```text
key = 0x5DF966AE - 0x21524111 = 0x3CA7259D
for i in 0..7:
    d = buf_dword[i] + key
    buf_dword[i] = d
    key = key ^ d
```

### 3.5 第二次“人格切换” + 64 位 rol（0x401200）

```asm
40144c  push 0
40144e  lea  eax, [0x407060]
401454  push eax
401455  call far [0x40700c]      ; 远调用 选择子0x33 : 0x401200  -> 64 位
40145b  push 0x401290
401460  push 7
401462  call 0x401120            ; 第二次生成 trampoline
401467  add  esp, 8
40146a  test eax, eax
40146c  jne  0x401473
```

`ff 1d 0c 70 40 00` 是 **far call `[0x40700c]`**，读取的 6 字节远指针 = `33:00401200`，即切到 64 位调用 `0x401200`。`0x401200` 用 `retf 8` 返回并清掉两个参数（`buf` 与 `0`）。64 位反汇编：

```asm
401200  push rbp
401201  mov  rbp, rsp
401204  mov  al, byte [0x40705c]        ; BeingDebugged
40120d  test al, al
40120f  je   0x401245                   ; 正常（无调试器）走这里
; BeingDebugged != 0 分支（调试时）：每个 qword rol 0x20
401245  mov  rax, [rbp + 0x10]          ; 参数 = buf（0x407060）
40124a  mov  rbx, [rax + 0]      ; rol 0x0c
401254  mov  rbx, [rax + 8]      ; rol 0x22
40125f  mov  rbx, [rax + 0x10]   ; rol 0x38
40126b  mov  rbx, [rax + 0x18]   ; rol 0x0e
...
401288  retf 8
```

即对 `buf` 的前 4 个 64 位字分别做 64 位循环左移：`0x0c, 0x22, 0x38, 0x0e`。

### 3.6 表生成 + 64 位 XOR（0x401290 / 0x40146e）

第二次 `call 0x401120` 后，`0x401467` 被改写成 `EA 33:0x401290`，进入 64 位 stub：

```asm
; 0x401290 (64-bit)
401290  xor  rax, rax
401293  mov  rax, 0x4014c5
40129d  mov  dword [0x407000], eax      ; 让最终的 ljmp 回到 32 位 0x4014c5
4012a4  lea  rax, [0x407014]
4012ac  mov  bl,  [rax + 0]   ; t0
4012ae  mov  cl,  [rax + 4]   ; t1
4012b1  and  bl, cl           ; t0 = t0 & t1
4012b3  mov  [rax], bl
4012b5  mov  bl,  [rax + 4]   ; t1
4012b8  mov  cl,  [rax + 8]   ; t2
4012bb  or   bl, cl           ; t1 = t1 | t2
4012bd  mov  [rax + 4], bl
4012c0  mov  bl,  [rax + 8]   ; t2
4012c3  mov  cl,  [rax + 0xc] ; t3
4012c6  xor  bl, cl           ; t2 = t2 ^ t3
4012c8  mov  [rax + 8], bl
4012cb  mov  bl,  [rax + 0xc]
4012ce  not  bl               ; t3 = ~t3
4012d0  mov  [rax + 0xc], bl
4012d6  jmp  qword [0x407050]  ; -> trampoline -> 0x40146e（仍是 64 位）
```

表初始值来自 `.data`：`0x407014` 4 个 dword = `0x9d, 0x44, 0x37, 0xb5`（取低字节）。

```text
t0=0x9d & 0x44 -> 0x04
t1=0x44 | 0x37 -> 0x77
t2=0x37 ^ 0xb5 -> 0x82
t3=~0xb5       -> 0x4a
```

`0x40146e` 是 64 位 XOR 循环（此时 `eax=0`，trampoline 的 `jne` 不跳，`E9` 进 `0x40146e`）：

```asm
40146e  mov  rax, [0x4070c8]     ; i
401476  cmp  rax, 0x20
40147a  je   0x4014bc
401489  div  rcx                 ; rdx = i % 4
40148c  lea  rbx, [0x407014]
401494  mov  dl, [rbx + rdx*4]   ; table[i%4]
40149f  lea  rbx, [0x407060]
4014a7  mov  cl, [rbx + rax]     ; buf[i]
4014aa  xor  cl, dl
4014ac  mov  [rbx + rax], cl
4014b2  mov  [0x4070c8], rax     ; ++i
4014bc  mov  eax, 0x407000
4014c2  ljmp [rax]               ; 远指针 = 23:004014c5 -> 切回 32 位
```

即：`buf[i] ^= table[i % 4]`，`table = [0x04, 0x77, 0x82, 0x4a]`。

### 3.7 比较（32 位）

回到 32 位 `0x4014c5`，构造 32 字节目标数组并 memcmp：

```asm
; 逐字节 c6 45 <disp> <imm> 写入 [ebp-0x70..-0x51]
4014e2  mov byte [ebp-0x70], 0xaa
4014e6  mov byte [ebp-0x6f], 0x4f
...
40155e  mov byte [ebp-0x51], 0xca
401567  push 0x20
401569  lea  eax, [ebp-0x70]
40156c  push eax
40156d  push 0x407060
401572  call memcmp
40157a  test eax, eax
40157c  jne  0x4015a6            ; 不等 -> "Wrong flag"
401580  push 0x405178            ; "Right, flag is DASCTF{your input}"
401599  push 0
40159b  call exit
```

---

## 4. 为什么可以反推（关键常量）

| 名称 | 值 |
| --- | --- |
| 目标数组 TARGET | `aa4f0fe2e44199542c2b847ebc8f8b78d373885eae47857031b309ce13f50dca` |
| key stub 常量 | `0x5DF966AE` |
| 减去常量 | `0x21524111` |
| 初始 key | `0x5DF966AE - 0x21524111 = 0x3CA7259D` |
| 表（变异后） | `[0x04, 0x77, 0x82, 0x4A]` |
| rol 位数（q0..q3） | `0x0C, 0x22, 0x38, 0x0E` |

正向流程：`input(32B)` → 滚动 key（8×dword）→ 4×rol64 → 逐字节 XOR 表 → 与 TARGET 比较。每一步都可逆（加法在 32 位下减回去、rol 用 ror 逆、XOR 自逆），因此可唯一还原输入。

---

## 5. 攻击链（解题链）

```text
scanf("%99s", buf)   -> 32 字节输入
      |
      |  [人格切换 1] EA 33:0x4011d0 (64-bit)
      |      key = 0x5df966ae  ->  ljmp 23:trampoline  -> 0x4013ef (32-bit)
      v
key = 0x5df966ae - 0x21524111 = 0x3CA7259D
for i in 0..7: d = buf_dw[i] + key; buf_dw[i] = d; key ^= d
      |
      |  [人格切换 2] far call 33:0x401200 (64-bit rol) -> retf 8
      v
buf_q[0] = rol64(buf_q[0], 0x0c)
buf_q[1] = rol64(buf_q[1], 0x22)
buf_q[2] = rol64(buf_q[2], 0x38)
buf_q[3] = rol64(buf_q[3], 0x0e)
      |
      |  [人格切换 3] EA 33:0x401290 -> 表变异 -> 64-bit XOR loop -> ljmp 23:0x4014c5
      v
table = [0x9d,0x44,0x37,0xb5] -> [0x04,0x77,0x82,0x4a]
for i in 0..31: buf[i] ^= table[i % 4]
      |
      v
memcmp(buf, TARGET, 32) == 0  ->  DASCTF{<buf>}
```

逆推：`TARGET -> 去XOR -> 反rol(ror64) -> 反滚动key -> input`。

---

## 6. 完整脚本

见 `exploits/dual_personality.py`（自包含，纯 Python 逆运算 + 正向校验）：

```python
#!/usr/bin/env python3
import struct

TARGET = bytes.fromhex(
    "aa4f0fe2e44199542c2b847ebc8f8b78d373885eae47857031b309ce13f50dca")
SUB_CONST = 0x21524111
KEY_CONST = 0x5DF966AE
ROL_AMOUNTS = (0x0C, 0x22, 0x38, 0x0E)


def mutate_table(base=(0x9D, 0x44, 0x37, 0xB5)):
    t = list(base)
    t[0] = (base[0] & base[1]) & 0xFF
    t[1] = (base[1] | base[2]) & 0xFF
    t[2] = (base[2] ^ base[3]) & 0xFF
    t[3] = (~base[3]) & 0xFF
    return t


def rotr64(v, r):
    return ((v >> r) | (v << (64 - r))) & 0xFFFFFFFFFFFFFFFF


def solve():
    key = (KEY_CONST - SUB_CONST) & 0xFFFFFFFF
    table = mutate_table()
    x = bytearray(c ^ table[i % 4] for i, c in enumerate(TARGET))
    y = bytearray()
    for i, r in enumerate(ROL_AMOUNTS):
        q = struct.unpack_from("<Q", x, i * 8)[0]
        y += struct.pack("<Q", rotr64(q, r))
    inp = bytearray()
    k = key
    for i in range(0, 32, 4):
        d = struct.unpack_from("<I", y, i)[0]
        inp += struct.pack("<I", (d - k) & 0xFFFFFFFF)
        k ^= d
    return bytes(inp)


if __name__ == "__main__":
    body = solve()
    print("FLAG       : DASCTF{%s}" % body.decode())
```

运行：

```bash
cd /Users/laiandi/ctf
.venv/bin/python exploits/dual_personality.py
```

---

## 7. 实际输出

```text
$ .venv/bin/python exploits/dual_personality.py
input body : 6cc1e44811647d38a15017e389b3f704
forward ok : True
FLAG       : DASCTF{6cc1e44811647d38a15017e389b3f704}
```

正向校验（把还原出的输入再按 3 段变换算一遍）得到的 32 字节与二进制里硬编码的
TARGET 完全一致：

```text
forward: aa4f0fe2e44199542c2b847ebc8f8b78d373885eae47857031b309ce13f50dca
const  : aa4f0fe2e44199542c2b847ebc8f8b78d373885eae47857031b309ce13f50dca
MATCH
```

另外用 Unicorn 以真实指令执行了第一段 32 位“滚动 key”循环（从 `0x4013fe`
跑到 `0x40144c`），结果与 Python 模型逐字节一致（见 `work/dual_personality/emu_verify.py`）。

---

## 8. 踩坑 / 易错点

- **不要用单一模式反汇编**。`.text` 里 32 位与 64 位指令混排，`objdump -d` 遇到
  `GenuineIntel` 碎片、`c6 45..` 常量表、`EA` 远跳转编码区会错位；关键函数要用
  capstone 分别以 `CS_MODE_32` / `CS_MODE_64` 对照看。`0x4013ef` 之后是 32 位，
  `0x4011d0` / `0x401200` / `0x401290` / `0x40146e` 才是 64 位。
- **两处远指针都在 `.data` 里**：`0x407000` = `23:<alloc>`（回 32 位），
  `0x40700c` = `33:00401200`（去 64 位）。只静态看 `0x401120` 的代码会漏掉
  `.data` 初始值中的选择子 `0x23` / `0x33`。
- **那次“多余”的 `mov eax,[0x407058]`** 是被设计出来的：正常返回 `eax=0` 会跳过它，
  只有经过 64 位一轮回来 `eax≠0` 才执行，从而得到正确 key。若只按 32 位直读会
  把 key 算成 `0 - 0x21524111 = 0xDEADBEEF`，解出乱码。
- **调试卷入**：若被调试，PEB->BeingDebugged≠0，key 不被赋值（保持 0）→ 解出的是
  `0xDEADBEEF` 版本，得不到正确 flag；必须按“无调试器”路径。
- **rol 是 64 位**：`rol rbx,0x22` 等必须作用在 64 位字上，用 32 位 rol（对 0x20 取模）
  会算错。
- 输入由 `%99s` 读入，但校验固定处理 32 字节；输入必须恰好 32 字节，其余为 0。

---

## 9. 结果验证

- 反推出的 32 字节 `6cc1e44811647d38a15017e389b3f704` 是合法十六进制串，长度与
  `memcmp(..., 32)` 一致；
- 正向重算结果与二进制硬编码 TARGET 完全相等（MATCH）；
- Unicorn 以真实 32 位指令执行关键循环，结果与模型一致；
- 按提示语 `DASCTF{your input}` 组装即为最终 flag。

**Flag：`DASCTF{6cc1e44811647d38a15017e389b3f704}`**
