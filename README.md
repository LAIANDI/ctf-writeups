# CTF Writeups

个人 CTF 题解，按题目类型记录分析过程、关键漏洞、解题脚本和最终结果。

目录结构：`<分类>/<题目名>/wp.md`

## Pwn (8)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| fmt28114 | CTFshow | 格式化字符串、栈上信息泄露 | [wp](pwn/fmt28114/wp.md) |
| glibc_master | 2022 长城杯 高校组 | 堆 UAF、负下标 OOB、House of Apple 2 FSOP | [wp](pwn/glibc_master/wp.md) |
| pwn109 | CTFshow | 格式化字符串、栈地址泄露、栈上 shellcode | [wp](pwn/pwn109/wp.md) |
| pwn117 | CTFshow | SSP Leak、栈溢出、`argv[0]` 覆盖 | [wp](pwn/pwn117/wp.md) |
| pwn82 | CTFshow | 32 位 ret2libc | [wp](pwn/pwn82/wp.md) |
| pwn83 | CTFshow | 32 位栈溢出、ret2libc | [wp](pwn/pwn83/wp.md) |
| superheap | CISCN 2024 SuperHeap | Go + protobuf、堆溢出、tcache poisoning、House of Some、ORW | [wp](pwn/superheap/wp.md) |
| ttt | CTFshow | 整数溢出、数组越界、游戏逻辑绕过 | [wp](pwn/ttt/wp.md) |

## Crypto (4)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| cha | — | 线性递推 + 矩阵快速幂 + AES-ECB | [wp](crypto/cha/wp.md) |
| linearAlgebra | 羊城杯 2022 | 线性代数 + 格约化（LLL/BKZ） | [wp](crypto/linearAlgebra/wp.md) |
| lrsa | DASCTF | RSA + 二维格约化 | [wp](crypto/lrsa/wp.md) |
| task | — | 四元数群上的离散对数 | [wp](crypto/task/wp.md) |

## Reverse (2)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| Re2 | 2022 网鼎杯 青龙组 | UPX 改段名脱壳、Unicorn 静态脱壳 | [wp](reverse/Re2/wp.md) |
| strangeapp | 湾区杯 2025 | Android 脱壳、DEX 指令还原 | [wp](reverse/strangeapp/wp.md) |

## Misc (1)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| duomaomao | 羊城杯 2022 | 流量提取、TLS keylog 解密、logistic map 隐写、MaxiCode | [wp](misc/duomaomao/wp.md) |

---

题解均为个人复现整理，Flag 仅作记录用途。
