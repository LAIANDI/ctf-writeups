# CTF Writeups

个人 CTF 题解，按方向组织。重点是**分析过程、漏洞成因和可复现的利用脚本**，而不是只贴 flag。

> 所有 flag 已打码（`flag{redacted}`）；部分题目附件未收录，请以赛事官方发布为准。
> 仅用于学习与防御研究，请勿用于未授权的目标。

## Pwn

| 题目 | 赛事 / 平台 | 考点 | Writeup |
|---|---|---|---|
| glibc_master | 2022 长城杯 高校组 | 堆 UAF、负下标 OOB、House of Apple 2 FSOP | [pwn/glibc_master.md](pwn/glibc_master.md) |
| superheap | CISCN 2024 | Go + protobuf、堆溢出、tcache poisoning、House of Some、ORW | [pwn/superheap.md](pwn/superheap.md) |
| msgboard | DASCTF | 格式化字符串泄栈、短溢出 `leave;ret` 栈迁移、跳 `read` 尾部二次读、ORW（seccomp 仅禁 `execve`） | [pwn/msgboard.md](pwn/msgboard.md) |
| pwn4 | 归档 / DASCTF 系列 | 堆 off-by-null、伪造 chunk 头造成 overlap、泄 libc、tcache poisoning `__free_hook` | [pwn/pwn4.md](pwn/pwn4.md) |
| minihttpd | CCB CISCN 2025 Quals | 非 PIE 栈溢出、无 `pop rdx`、借 `rdx` 残留 + 内部 `read_line` / `serve_file` 实现任意文件读 | [pwn/minihttpd.md](pwn/minihttpd.md) |
| pwn117 | CTFshow | SSP Leak、栈溢出、`argv[0]` 覆盖 | [pwn/pwn117.md](pwn/pwn117.md) |

## Crypto

| 题目 | 赛事 / 平台 | 考点 | Writeup |
|---|---|---|---|
| linearAlgebra | 羊城杯 2022 | 线性代数、格约化（LLL / BKZ） | [crypto/linearAlgebra.md](crypto/linearAlgebra.md) |
| cha | — | 线性递推、矩阵快速幂、AES-ECB | [crypto/cha.md](crypto/cha.md) |

## 建议阅读顺序

1. `pwn117`（栈溢出 + SSP Leak，入门）
2. `pwn4`（off-by-null → overlap → tcache，堆入门）
3. `msgboard`（fmt + 栈迁移 + ORW，综合）
4. `minihttpd`（无 pop rdx 的另类 ROP）
5. `glibc_master`（House of Apple 2，FSOP）
6. `superheap`（Go + protobuf + House of Some，较难）

## 目录约定

```text
pwn/<题目>.md
crypto/<题目>.md
```

每篇包含：分析过程、漏洞成因、利用思路、关键 exp（代码块）以及可复现的交互步骤。

> 部分题目的完整 exploit 脚本未随仓库发布（依赖赛事附件或特定环境），文中保留了关键代码和交互过程。

## 环境

- `pwntools`、`pwndbg`、`ROPgadget`、`one_gadget`
- 题目自带的 libc / ld 优先，用 `patchelf` 或 `ld-linux --library-path` 对齐版本

## License

- 代码（`*.py` / `*.c` / `*.sh`）：MIT
- 文字（`*.md`）：CC BY-NC-SA 4.0

如果这些 writeup 帮到了你，欢迎 star；转载请注明出处。
