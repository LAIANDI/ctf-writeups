---
title: "躲猫猫 (Hide & Seek)"
ctf: "羊城杯 2022"
date: 2026-09-21
category: misc
difficulty: medium
flag_format: "GWHT{...}"
author: ""
---

# 躲猫猫 (Hide & Seek) — 详细 Writeup

## 0. 题目信息

- 赛事：2022 羊城杯网络安全大赛
- 方向：Misc
- 附件：`MISC附件/task.zip`（解压得到 `task.pcapng`，约 10 MB）
- 考点：HTTP/FTP 流量提取、TCP 流重组、Zip 结构分析、TLS keylog 解密、
  逻辑斯蒂映射（logistic map）隐写的逆向、MaxiCode 二维码识别
- Flag：`GWHT{ozqgVLoI1DvK8giNVdvGslr_aZKKwNuv_q-FzqB5N3hHHqn3}`

## 1. 初步侦察

```bash
$ file task.pcapng
task.pcapng: pcapng capture file - version 1.0
```

用 scapy 统计一下（没有 wireshark 时的替代方案）：

```python
from scapy.all import PcapNgReader
from collections import Counter
c = Counter()
for pkt in PcapNgReader("task.pcapng"):
    c[pkt.lastlayer().name] += 1
print(c.most_common())
# [('Padding', 9236), ('Raw', 7292), ('TCP', 1795), ('DNS', 38), ('ARP', 14)]
```

共 **18375 个包**，其中绝大多数是 TLS 加密流量。先把 TCP 会话按
`(src,sport,dst,dport)` 分组，提取出主要通信对：

| 主机 | 角色 |
| --- | --- |
| `192.168.31.235` | 受害者 Windows 主机（Chrome UA） |
| `192.168.31.190:8888` | `web_final` 图片分享站，署名 `Fr3Nky@GWHT` |
| `192.168.5.1:21` | FTP 服务器（vsFTPd 3.0.5） |
| `36.139.153.197:42741` | 大量短连接 TLS（干扰项） |
| `183.x.x.x:443` | CDN / 干扰项 |

HTTP 明文请求汇总后，关键的两条是：

```text
192.168.31.235:14344 -> 192.168.31.190:8888   POST /web_final/upload.php   (8 MB 图片上传)
192.168.31.235:14397 -> 192.168.5.1:50243      (FTP 数据通道，important.zip)
```

## 2. 提取上传的图片 `missing_cat.png`

### 2.1 定位上传请求

`14344 -> 8888` 这一路流里只有两个请求，第一个就是大文件上传：

```text
POST /web_final/upload.php HTTP/1.1
Host: 192.168.31.190:8888
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqqMMOAkjoH9jOQCM
Content-Length: 8074971
Cookie: PHPSESSID=akhmbunbc9ir48tc9jcr3a4gs4
```

multipart 体：

```text
------WebKitFormBoundaryqqMMOAkjoH9jOQCM
Content-Disposition: form-data; name="file11"

C:\fakepath\missing_cat.png
------WebKitFormBoundaryqqMMOAkjoH9jOQCM
Content-Disposition: form-data; name="file"; filename="missing_cat.png"
Content-Type: image/png
<PNG data...>
------WebKitFormBoundaryqqMMOAkjoH9jOQCM--
```

### 2.2 关键坑：TCP 流必须去重重组

如果偷懒把同一方向的所有 TCP payload **按 seq 排序后直接拼接**，由于
网络存在**重传**，会把重复的字节也拼进去，导致 PNG 中间出现损坏的 chunk：

```text
0x180141  IDAT ...        <- 正常
0x180141  76 ce ca ca 5a 5f 5f 57   <- 长度字段变成 0x76cecaca，类型 "Z__W"
```

这种图片 `PIL.Image.open().load()` 会直接报 `Truncated File Read`。

正确的重组方式是**按序号落位、重叠部分去重**：

```python
def reassemble(pkts):          # pkts: [(seq, payload), ...]
    if not pkts:
        return b""
    base = pkts[0][0]
    buf, maxend = {}, 0
    for seq, data in pkts:
        rel = (seq - base) & 0xffffffff
        if rel > 2**31:        # 处理 32 位序号回绕
            rel -= 2**32
        for k, b in enumerate(data):
            buf[rel + k] = b
        maxend = max(maxend, rel + len(data))
    return bytes(buf.get(k, 0) for k in range(maxend))
```

重组后的大小与 `Content-Length` 完全对得上（`8076210 - 头部 = 8074971`），
PNG 也变成结构合法的图片（126 个 chunk，`IHDR`/`IDAT`/`IEND` 齐全）：

```text
missing_cat.png: PNG image data, 1800 x 1800, 8-bit/color RGB, non-interlaced
```

## 3. 提取 FTP 上的 `important.zip`

### 3.1 FTP 明文凭据

FTP 控制流（`192.168.5.1:21 <-> 192.168.31.235:14395`）是明文的：

```text
220 (vsFTPd 3.0.5)
USER root
331 Please specify the password.
PASS 83822655
230 Login successful.
CWD /dev/ftp/GWHT/
TYPE I
PASV            -> 227 Entering Passive Mode (192,168,5,1,196,67)   # 端口 196*256+67 = 50243
STOR important.zip
```

### 3.2 从数据通道取出压缩包

`192.168.5.1:50243 -> 192.168.31.235:14397` 的载荷以 `PK\x03\x04` 开头，
就是 `important.zip`（这也正是 FTP 里的 `STOR important.zip`）。

> 题目原文提到"压缩包导出来发现已经损坏，winrar 修复一下"。原因是
> 简单拼接同样受重传影响；用上面的去重重组即可得到完好的 zip。

## 4. 分析 zip 结构

```text
$ unzip -lv important.zip
 Length   Method    Size  Date              CRC-32    Name
    1183  Defl:N      524  08-09-2022 17:32  bd1df5fc  hide&seek.py
   15748  Defl:N     5689  08-09-2022 23:13  ffdfe32e  key.log
     199  Defl:N      109  08-09-2022 17:32  2aa4d381  secret
```

再看 central directory 的 **general purpose bit flag**：

| 文件 | flag | 是否加密 |
| --- | --- | --- |
| `hide&seek.py` | `0x0001` | 加密 |
| `key.log` | `0x0000` | **未加密（可直接提取）** |
| `secret` | `0x0001` | 加密 |

```python
import struct
d = open("important.zip","rb").read()
i = 0
while True:
    j = d.find(b"PK\x01\x02", i)
    if j < 0: break
    flag   = struct.unpack("<H", d[j+8:j+10])[0]
    method = struct.unpack("<H", d[j+10:j+12])[0]
    nlen   = struct.unpack("<H", d[j+28:j+30])[0]
    name   = d[j+46:j+46+nlen]
    print(name, hex(flag), method)
    i = j + 46 + nlen
# b'hide&seek.py' 0x1 8
# b'key.log'      0x0 8     <- 没有加密
# b'secret'       0x1 8
```

所以 `key.log` 无需密码即可解出。

## 5. `key.log` 与 TLS 解密

`key.log` 是一个 **SSLKEYLOGFILE**（TLS 会话密钥日志），内容形如：

```text
CLIENT_RANDOM 23ca4a17...c05e 9139d5c1...9f5    (TLS1.2 master secret)
CLIENT_HANDSHAKE_TRAFFIC_SECRET cdb7d920...45db8 fc4659d4...22a8  (TLS1.3)
SERVER_HANDSHAKE_TRAFFIC_SECRET cdb7d920...45db8 2e84b5b8...35fd
CLIENT_TRAFFIC_SECRET_0 cdb7d920...45db8 1ad39fbc...27fc
SERVER_TRAFFIC_SECRET_0 cdb7d920...45db8 6c9f5dbb...71b7
EXPORTER_SECRET ...
```

把该文件作为 Wireshark 的 `(Pre)-Master-Secret log filename`
（或 `tls.keylog_file`）即可解密流量中对应的 TLS 会话。题目中解密后
得到**一张写着压缩包密码的图片**：

```text
压缩包密码：20079651941337428
```

> 说明：
> 1. `key.log` 里同时存在 TLS1.2 的 `CLIENT_RANDOM`（第二个字段是
>    master secret）和 TLS1.3 的各类 `*_TRAFFIC_SECRET`。
> 2. 提供该 keylog 就是本题 "躲猫猫" 的核心：攻击者把 keylog 藏进
>    压缩包，却漏了它没有被加密。

用密码解压：

```bash
$ unzip -P 20079651941337428 important.zip
# hide&seek.py / key.log / secret
```

## 6. 逆向 `hide&seek.py`

```python
# hide&seek.py
from PIL import Image
from numpy import array, zeros, uint8
import cv2
from secret import get_x_y

image = cv2.imread("cat.png")                             # 原图（flag 图）
img_gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
imagearray = array(img_gray)
h, w = len(imagearray), len(imagearray[0])

x, y = get_x_y()                                          # 从 secret 读种子参数
x1 = round(x/y*0.001,    16); u1 = y*3650/x
x2 = round(x/y*0.00101,  16); u2 = y*3675/x
x3 = round(x/y*0.00102,  16); u3 = y*3680/x
kt = [x1, x2, x3]

temp_image = zeros(shape=[h, w, 3], dtype=uint8)
for i in range(h):
    for j in range(w):
        x1 = u1*x1*(1-x1)                                 # 逻辑斯蒂映射
        x2 = u2*x2*(1-x2)
        x3 = u3*x3*(1-x3)
        r1, r2, r3 = int(x1*255), int(x2*255), int(x3*255)  # 量化成字节
        for t in range(3):
            temp_image[i][j][t] = (((r1+r2) ^ r3) + imagearray[i][j][t]) % 256
Image.fromarray(temp_image).save("missing_cat.png")
```

`secret` 中保存种子 `x, y`：

```text
5999540678407978169965856946811257903979429787575580150595711549672916183293763090704344230372835328
6310149030391323406342737832910952782997118359318834776480172449836047279615976753524231989362688
```

注意 `x/y ≈ 950.7`，所以：

- `x1 = round(x/y*0.001, 16)     ≈ 0.9507763841254185`
- `u1 = y*3650/x = 3650/(x/y)    ≈ 3.8389678802944713`
- `u2 ≈ 3.8652621808444336`，`u3 ≈ 3.8705210409544257`

三个 `u` 都落在混沌区间 `(3.57, 4)`，产生的序列近似随机，但**完全由种子决定**。

### 6.1 逆运算

加密是加法（模 256），解密就是减去同一串密钥流：

```python
temp = (imagearray[i][j][t] - ((r1 + r2) ^ r3)) % 256
```

对 `missing_cat.png` 做同样的遍历、扣除密钥流，即可得到**原图 `cat.png`**。
上面的密钥流只和 `(i,j)` 有关，与像素值无关，所以加密/解密时的密钥流完全一致，
逐像素相减即可（3 个通道减同一个值）。

## 7. 还原结果：被"藏猫"的二维码

解出来的图（`decoded_cat.png`）是一张大尺寸二维码，但有两个特征：

1. 每一个"点"不是方形，而是**六边形**，按蜂窝状（相邻行错位半个间距）排列；
2. 正中央是一张猫的照片，把二维码的定位区整个挖空了。

这正对应题目名"躲猫猫"：猫把定位图案藏了起来。

## 8. 识别二维码：MaxiCode

### 8.1 判断码制

采样六边形中心，量出栅格：

- 一共 **33 行**，行距 `49 px`；
- **偶数行 30 个模块**，起始 `x = 57.5`，列距 `57 px`；
- **奇数行 29 个模块**，起始 `x = 85.5`（即右移半个列距）。
- 图像 1800×1800，首行 `y = 83.5`。

`33 行 × 30 列、六边形、中心有圆形定位靶` —— 这就是 **MaxiCode**
（UPS 码）。

### 8.2 MaxiCode 的结构

MaxiCode 的核心信息在 zxing-cpp 源码里（`core/src/maxicode/`）：

- `MCBitMatrixParser.cpp` 中有一张 `BITNR[33][30]` 表，把每个模块位置映射到
  `0..863` 的 bit（144 个 6-bit 码字），`-1/-2/-3` 表示不承载数据；
- `MCReader.cpp` 的 `ExtractPureBits()` 通过**外接矩形**按
  `MATRIX_WIDTH=30`、`MATRIX_HEIGHT=33` 均匀采样：

```cpp
// 偶数行：ix = left + (x + 0.5) * width/30
// 奇数行：ix = left + (x + 1.0) * width/30   （右移半格）
int ix = left + (x * width + width / 2 + (y & 0x01) * width / 2) / 30;
int iy = top  + (y * height + height / 2) / 33;
```

关键点：**解码器并不依赖中心定位图案**，它只按外接矩形等分采样。所以
中心被猫挖空并不影响解码——因为那部分正好是 `BITNR` 里的 `-1/-2/-3`
（定位靶区域），不承载数据。（题目给出的解决方案就是用 PS 把定位靶补上，
再用在线识别器读出结果。）

### 8.3 还原与解码

按上面的几何把 `decoded_cat.png` 采样成 `33×30` 的 `0/1` 矩阵，再按
`BITNR` 重新渲染成一张干净的 MaxiCode，用 `zxing-cpp` 解码：

```python
import zxingcpp
res = zxingcpp.read_barcodes(img, formats=zxingcpp.BarcodeFormat.MaxiCode)
print(res[0].text)
# GWHT{ozqgVLoI1DvK8giNVdvGslr_aZKKwNuv_q-FzqB5N3hHHqn3}
```

## 9. 完整 Exploit

脚本：`exploits/duomaomao_solve.py`

```python
#!/usr/bin/env python3
# 羊城杯 2022 MISC - 躲猫猫 (Hide & Seek)
# Requires: pip install numpy pillow zxing-cpp

import numpy as np
from PIL import Image, ImageDraw

BASE = "/Users/laiandi/ctf/work/misc1"
# 33x30 位映射，来自 zxing-cpp core/src/maxicode/MCBitMatrixParser.cpp 的 BITNR
# 完整脚本 exploits/duomaomao_solve.py 中已内联该 33 行常量表
BITNR = [...]


def decode_missing_cat():
    """逆逻辑斯蒂映射，把 missing_cat.png 还原成 decoded_cat.png"""
    lines = [l.strip() for l in open(f"{BASE}/out_pw/secret") if l.strip()]
    x, y = int(lines[0]), int(lines[1])

    arr = np.array(Image.open(f"{BASE}/missing_cat2.png").convert("RGB")).astype(np.int16)
    h, w, _ = arr.shape

    x1 = round(x / y * 0.001, 16);     u1 = y * 3650 / x
    x2 = round(x / y * 0.00101, 16);   u2 = y * 3675 / x
    x3 = round(x / y * 0.00102, 16);   u3 = y * 3680 / x

    ks = np.empty(h * w, dtype=np.uint8)
    n = 0
    for _ in range(h):
        for _ in range(w):
            x1 = u1 * x1 * (1 - x1)
            x2 = u2 * x2 * (1 - x2)
            x3 = u3 * x3 * (1 - x3)
            r1, r2, r3 = int(x1 * 255), int(x2 * 255), int(x3 * 255)
            ks[n] = ((r1 + r2) ^ r3) & 0xFF
            n += 1
    ks = ks.reshape(h, w, 1)
    out = ((arr - ks.astype(np.int16)) % 256).astype(np.uint8)
    Image.fromarray(out).save(f"{BASE}/decoded_cat.png")


def sample_and_decode():
    """把六边形图案采样成 33x30 矩阵，重绘 MaxiCode 后解码"""
    our = np.array(Image.open(f"{BASE}/decoded_cat.png").convert("L"))
    H, W = our.shape

    def black(px, py):
        xi, yi = int(round(px)), int(round(py))
        return 1 if 0 <= xi < W and 0 <= yi < H and our[yi, xi] < 128 else 0

    M = np.zeros((33, 30), np.uint8)
    for r in range(33):
        for c in range(30):
            if BITNR[r][c] == -3:
                continue
            cx = 57.5 + 57 * c if r % 2 == 0 else 85.5 + 57 * c
            cy = 83.5 + 49 * r
            M[r, c] = black(cx, cy)

    pitch, margin = 12, 6
    im = Image.new("L", (margin * 2 + 30 * pitch, margin * 2 + 33 * pitch), 255)
    d = ImageDraw.Draw(im)
    for r in range(33):
        for c in range(30):
            if BITNR[r][c] == -3 or M[r, c] == 0:
                continue
            x0 = margin + (c * pitch if r % 2 == 0 else int((c + 0.5) * pitch))
            d.rectangle([x0, margin + r * pitch, x0 + pitch - 1,
                         margin + (r + 1) * pitch - 1], fill=0)
    im.save(f"{BASE}/render_m.png")

    import zxingcpp
    for b in zxingcpp.read_barcodes(np.array(im), formats=zxingcpp.BarcodeFormat.MaxiCode):
        if b.valid:
            return b.text


if __name__ == "__main__":
    decode_missing_cat()
    print("FLAG:", sample_and_decode())
```

运行：

```bash
$ .venv/bin/python exploits/duomaomao_solve.py
FLAG: GWHT{ozqgVLoI1DvK8giNVdvGslr_aZKKwNuv_q-FzqB5N3hHHqn3}
```

## 10. 攻击链总结

```text
HTTP POST /web_final/upload.php
        │  (TCP 流去重重组)
        ▼
  missing_cat.png (1800x1800, 被 logistic map 加密)
        ▲
        │
FTP STOR important.zip ──► hide&seek.py + key.log + secret
        │                             │
        │ key.log (SSLKEYLOGFILE)     │ secret 提供种子 x,y
        │ 未加密，可直接提取           │
        ▼                             ▼
   TLS 解密 ──► 得到图片 ──► zip 密码 20079651941337428
                                      │
                                      ▼
        逆 logistic 映射解密 missing_cat.png
                                      │
                                      ▼
        六边形 MaxiCode（定位靶被猫挖空）
                                      │
                采样 33x30 + BITNR + zxing-cpp
                                      │
                                      ▼
   GWHT{ozqgVLoI1DvK8giNVdvGslr_aZKKwNuv_q-FzqB5N3hHHqn3}
```

## 11. 踩坑与工具

- **TCP 重传**：pcap 里的流一定要按序号去重重组，否则 PNG/ZIP 都会"损坏"。
- **Zip 加密位**：看 central directory 的 flag 字段，`key.log` 没加密是本流程的突破口。
- **混沌映射的数值**：`x/y` 的量级容易看错，先打印 `x/y` 再解释 `x1/u1`。
- **MaxiCode**：本机没有 Wireshark 时，用 `zxing-cpp`（PyPI 有 cp39 macOS wheel）
  即可离线解码；其 `MCBitMatrixParser` 的 `BITNR` 表是还原的关键。
- **环境**：Python 3.9 + `numpy / pillow / zxing-cpp / scipy / scapy / pycryptodome`。

## Flag

```text
GWHT{ozqgVLoI1DvK8giNVdvGslr_aZKKwNuv_q-FzqB5N3hHHqn3}
```
