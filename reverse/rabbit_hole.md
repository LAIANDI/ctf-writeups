# rabbit_hole — Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目 | rabbit_hole |
| 分类 | Reverse |
| 附件 | `challenges/rabbit_hole_release.exe` |
| 附件 SHA256 | `dd9084a43fc4633a196e86a16be1d5cfeb55e0cccbc5fc4fe578cf65d073fdfa` |
| 文件格式 | PE32 (console) Intel 80386, for MS Windows |
| 环境 | 本机 Python 3（标准库），capstone（辅助反汇编） |
| Flag | `flag{54735c379e641a51ffac016a263bf6be}` |

程序提示（strings）：
```text
Help Alice find a way out of the rabbit hole:
Not a very good path dont you think? :)
If you think you do, then your flag will be: flag{md5(input)}
```

即输入一条路径，程序校验后把 `flag{md5(input)}` 作为结果——真正的目标是找到那条唯一正确路径。

## 2. Recon

```bash
$ file challenges/rabbit_hole_release.exe
PE32 executable (console) Intel 80386, for MS Windows

$ strings -n 6 challenges/rabbit_hole_release.exe | grep -i -e find -e path -e flag
If you think you do, then your flag will be: flag{md5(input)}
Help Alice find a way out of the rabbit hole:
Not a very good path dont you think? :)

$ .venv/bin/python -m capstone   # 用脚本 rdis.py 做递归下降反汇编
```

PE 节区（VA/RVA）：

| Section | RVA | VSize | raw_ptr |
| --- | --- | --- | --- |
| `.text` | 0x1000 | 0x1c6d | 0x400 |
| `.rdata` | 0x3000 | 0x2dec | 0x2200 |
| `.data` | 0x6000 | 0x410 | 0x5000 |

ImageBase = `0x400000`。关键校验循环在 `.text @ 0x401358` 起。

## 3. 漏洞分析

### 3.1 输入语义：21×21 迷宫路径

反汇编 `0x401358` 起逐字符处理输入：

```asm
mov  al, byte ptr [esi + edi]      ; 取输入字符
cmp  al, 104                        ; 'h'
jne  ...
dec  ebx                            ; row -= 1
sub  ecx, 21                        ; idx -= 21
...
cmp  al, 106                        ; 'j' -> row += 1 (idx += 21)
cmp  al, 107                        ; 'k' -> col -= 1 (--edx)
cmp  al, 108                        ; 'l' -> col += 1 (++edx)
```

- 字符集 `h/j/k/l`，移动：`h`=row−1、`j`=row+1、`k`=col−1、`l`=col+1。
- 越界检查 `0x4013a8`：`row/col ∈ [0,21)`，即 **21×21 网格**，索引 `idx = row*21 + col`。
- 起点 `(0,0)`，终点 `(20,20)`（`0x401321` 附近的初始索引与结束条件）。

### 3.2 格子开放判据

`0x4013ba`：

```asm
lea    eax, [ecx + edx]                       ; eax = idx
movzx  ecx, byte ptr [eax + 0x404208]         ; byte_table[idx]
xor    ecx, dword ptr [4*eax + 0x4043c8]      ; ^ dword_table[idx]
mov    eax, edx
shl    eax, 8                                  ; col << 8
xor    ecx, eax
xor    ecx, ebx                                ; ^ row
cmp    ecx, 1
jne    <reject>
```

即格子 `(row,col)` 开放 ⟺
```
byte_table[row*21+col] ^ dword_table[row*21+col] ^ (col<<8) ^ row == 1
```

两张表在 `.rdata`：byte 表 `0x404208`（441 字节），dword 表 `0x4043C8`（441 个 dword）。

### 3.3 干扰分支

`0x401419` 起有一段 FNV-1a（offset `0x050c5d1f`，prime `0x01000193`）在长度 16 的输入上迭代，命中 `0x61 8ff3 39`（小端 `1636823865`）会 `je 0x40149b` 跳到“成功”分支，反解得到 `flag{fake__flag}`——程序随后提示 `Not a very good path`，属于干扰。

## 4. 关键中间值

| 名称 | 值 |
| --- | --- |
| 网格 | 21×21，起点 `(0,0)`，终点 `(20,20)` |
| 字符→移动 | `h`=-21(上), `j`=+21(下), `k`=col-1(左), `l`=col+1(右) |
| 开放判据 | `byte[0x404208+i] ^ dword[0x4043c8+4i] ^ (col<<8) ^ row == 1` |
| byte 表 VA / file off | `0x404208` / `0x3408` |
| dword 表 VA / file off | `0x4043C8` / `0x35C8` |
| 开放格子数 | **188**（连通、无环 → 树；187 条边） |
| 唯一路径长度 | **134** |
| 路径字符串 | `jjjllllllllllllllljjjjjjjjkjjkkkkhhhhhhhkkkkkkkkkkjjjjllljjjlllhhhhlljjjjjjkkkkkkkkjjlllllllllllhhlllllhhhlhhhhhhhhlljjjjjjjjjjjjjjjjl` |
| 干扰 flag | `flag{fake__flag}`（长度 16 分支） |
| Flag | `flag{54735c379e641a51ffac016a263bf6be}` |

## 5. 攻击链

```
strings ──▶ "flag{md5(input)}" 提示 + "Help Alice find a way out"
   │
反汇编 .text@0x401358 ──▶ 识别 h/j/k/l + 21×21 网格 + 开放判据
   │
.rdata@0x404208/0x4043C8 ──▶ 重建 441 格迷宫（188 开放格，树）
   │
BFS (0,0)→(20,20) ──▶ 唯一 134 步路径
   │
md5(路径字符串) ──▶ 54735c379e641a51ffac016a263bf6be
   │
flag{54735c379e641a51ffac016a263bf6be}
```

## 6. 完整脚本

`exploits/rabbit_hole.py`：

```python
#!/usr/bin/env python3
"""rabbit_hole_release.exe — 21x21 maze reverse solver (stdlib only)."""
import hashlib, struct, sys
from collections import deque

IMG_BASE = 0x400000
SECTIONS = ((".text",0x1000,0x1c6d,0x400),
            (".rdata",0x3000,0x2dec,0x2200),
            (".data",0x6000,0x410,0x5000))
BYTE_TABLE_VA, DWORD_TABLE_VA = 0x404208, 0x4043C8
N = 21
START, GOAL = (0, 0), (20, 20)
MOVE = {(-1, 0): "h", (1, 0): "j", (0, -1): "k", (0, 1): "l"}

def va2off(va):
    rva = va - IMG_BASE
    for _n, sva, vsz, rptr in SECTIONS:
        if sva <= rva < sva + vsz:
            return rptr + (rva - sva)
    raise ValueError(hex(va))

def is_open(data, bt, dw, r, c):
    i = r * N + c
    b = data[bt + i]
    w = struct.unpack_from("<I", data, dw + 4 * i)[0]
    return (b ^ w ^ ((c << 8) & 0xFFFFFFFF) ^ r) == 1

def solve(path):
    data = open(path, "rb").read()
    bt, dw = va2off(BYTE_TABLE_VA), va2off(DWORD_TABLE_VA)
    prev = {START: None}; q = deque([START])
    while q:
        cur = q.popleft()
        if cur == GOAL: break
        r, c = cur
        for (dr, dc), _ in MOVE.items():
            nr, nc = r + dr, c + dc
            if 0 <= nr < N and 0 <= nc < N and is_open(data, bt, dw, nr, nc) \
                    and (nr, nc) not in prev:
                prev[(nr, nc)] = cur; q.append((nr, nc))
    route, cur = [], GOAL
    while prev.get(cur):
        pr, pc = prev[cur]
        route.append(MOVE[(cur[0]-pr, cur[1]-pc)]); cur = (pr, pc)
    route = "".join(reversed(route))
    return route, "flag{%s}" % hashlib.md5(route.encode()).hexdigest()

if __name__ == "__main__":
    exe = sys.argv[1] if len(sys.argv) > 1 else "rabbit_hole_release.exe"
    route, flag = solve(exe)
    print("route_len:", len(route)); print("route:", route); print("FLAG:", flag)
```

运行：

```bash
.venv/bin/python exploits/rabbit_hole.py challenges/rabbit_hole_release.exe
```

## 7. 实际输出

```text
$ .venv/bin/python exploits/rabbit_hole.py challenges/rabbit_hole_release.exe
route_len: 134
route: jjjllllllllllllllljjjjjjjjkjjkkkkhhhhhhhkkkkkkkkkkjjjjllljjjlllhhhhlljjjjjjkkkkkkkkjjlllllllllllhhlllllhhhlhhhhhhhhlljjjjjjjjjjjjjjjjl
FLAG: flag{54735c379e641a51ffac016a263bf6be}
```

## 8. 踩坑记录

- **长度 16 的线性/哈希校验是干扰**：`0x401419` 的 FNV-1a 分支能解出 `flag{fake__flag}`，但程序把它判为 `Not a very good path`。不要在这里停下。
- **迷宫告警“199 格 / 198 边”是误算**：按开放判据逐格验证，实际为 **188 开放格 / 187 边**，是一棵树，从而唯一路径存在（早期把索引或边界算错会得到 199）。
- **路径不是 flag 本身**：flag 是 `md5(路径字符串)`，路径字符串是 134 个 `h/j/k/l`，切勿对路径做额外编码。
- **起始/结束点**：起点索引 0 `(0,0)`，终点为索引 440 `(20,20)`，路径必须以到达 `(20,20)` 为准。

## 9. 验证

- 从原始 `.exe` 直接重建迷宫（byte/dword 两表在 `.rdata`），BFS 得唯一 134 步路径，与 muteki 会话黑板记录的唯一路径**逐字符一致**。
- `hashlib.md5(route.encode()).hexdigest() == 54735c379e641a51ffac016a263bf6be`，与题目给出的 `flag{md5(input)}` 规则吻合。
- 附件 SHA256 与题目信息一致；`flag{...}` 格式与 strings 提示一致。
