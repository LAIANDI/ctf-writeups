# CTF Writeups

个人 CTF 题解，按题目类型记录分析过程、关键漏洞、解题脚本和最终结果。

目录结构：`<分类>/<题目名>.md`

## Pwn (10)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| fmt28114 | CTFshow | 格式化字符串、栈上信息泄露 | [wp](pwn/fmt28114.md) |
| glibc_master | 2022 长城杯 高校组 | 堆 UAF、负下标 OOB、House of Apple 2 FSOP | [wp](pwn/glibc_master.md) |
| msgboard | DASCTF message board | 格式化字符串泄栈、短溢出 `leave;ret` 栈迁移、跳 read 尾部二次读、ORW（seccomp 仅禁 execve） | [wp](pwn/msgboard.md) |
| pwn109 | CTFshow | 格式化字符串、栈地址泄露、栈上 shellcode | [wp](pwn/pwn109.md) |
| pwn117 | CTFshow | SSP Leak、栈溢出、`argv[0]` 覆盖 | [wp](pwn/pwn117.md) |
| pwn4 | 归档 / DASCTF 系 | 堆 off-by-null、伪造 chunk 头造 overlap、泄 libc、tcache poisoning `__free_hook` | [wp](pwn/pwn4.md) |
| pwn82 | CTFshow | 32 位 ret2libc | [wp](pwn/pwn82.md) |
| pwn83 | CTFshow | 32 位栈溢出、ret2libc | [wp](pwn/pwn83.md) |
| superheap | CISCN 2024 SuperHeap | Go + protobuf、堆溢出、tcache poisoning、House of Some、ORW | [wp](pwn/superheap.md) |
| ttt | CTFshow | 整数溢出、数组越界、游戏逻辑绕过 | [wp](pwn/ttt.md) |

## Crypto (4)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| cha | — | 线性递推 + 矩阵快速幂 + AES-ECB | [wp](crypto/cha.md) |
| linearAlgebra | 羊城杯 2022 | 线性代数 + 格约化（LLL/BKZ） | [wp](crypto/linearAlgebra.md) |
| lrsa | DASCTF | RSA + 二维格约化 | [wp](crypto/lrsa.md) |
| task | — | 四元数群上的离散对数 | [wp](crypto/task.md) |

## Reverse (4)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| Dual_personality | DASCTF | Windows PE、Heaven's Gate 32/64 位混合代码、反调试 | [wp](reverse/Dual_personality.md) |
| Re2 | 2022 网鼎杯 青龙组 | UPX 改段名脱壳、Unicorn 静态脱壳 | [wp](reverse/Re2.md) |
| rabbit_hole | — | PE32 21×21 迷宫、唯一路径、`flag{md5(path)}` | [wp](reverse/rabbit_hole.md) |
| strangeapp | 湾区杯 2025 | Android 脱壳、DEX 指令还原 | [wp](reverse/strangeapp.md) |

## Web (2)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| go_session | — | gorilla/sessions 空 key 会话伪造、pongo2 SSTI、`{% include %}` 任意文件读 | [wp](web/go_session.md) |
| SecretVault | — | Go ReverseProxy hop-by-hop 头剥离（`Connection: X-User`）、Flask `X-User` 默认 admin | [wp](web/SecretVault.md) |

## Misc (2)

| 题目 | 赛事 / 平台 | 考点 | Writeup |
| --- | --- | --- | --- |
| duomaomao | 羊城杯 2022 | 流量提取、TLS keylog 解密、logistic map 隐写、MaxiCode | [wp](misc/duomaomao.md) |
| office_love_chain | 长城杯 2022 政企组 | docx 隐藏文字、PDF 位平面隐写（wbStego）、ZipCrypto、pptx 七进制颜色 | [wp](misc/office_love_chain.md) |

---

题解均为个人复现整理，Flag 仅作记录用途。
