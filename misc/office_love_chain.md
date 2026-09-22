# 办公室爱情（Office Love）— Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目 | 办公室爱情（Office Love） |
| 赛事 | 长城杯 2022 政企组 Misc（NSSCTF 复现版） |
| 分类 | Misc |
| 附件 | `challenges/misc1/沃德.docx` / `皮迪符.pdf` / `皮皮特的外套.zip` |
| 附件 SHA256 | `沃德.docx` = `3c0f70932f30bf244d69b733bd18e39685a14b91f9fdc38286ecd2bac65f689d`<br>`皮迪符.pdf` = `4d737c0ac686103dd8bad7084b9ca4a16b98fc7614718542fc32d07164757ee3`<br>`皮皮特的外套.zip` = `44ad777b3759c5940255e1abf3f508cd9209796337ac2f9ad2ab72f0c5039515` |
| 文件格式 | docx (OOXML) / PDF 1.5 / ZIP (传统 ZipCrypto) / pptx (OOXML) |
| 环境 | 本机 Python 3（`zipfile` + `unzip`），wbStego4open |
| Flag | `flag{10ve_exCe1_!!!}` |

文件名谐音：**沃德=Word、皮迪符=PDF、皮皮特=PPT** —— 已暗示这是 Office 三件套的链式解锁题。

## 2. Recon

```bash
$ file challenges/misc1/*
沃德.docx:        Microsoft Word 2007+
皮迪符.pdf:       PDF document, version 1.5
皮皮特的外套.zip: Zip archive data, at least v2.0 to extract, encrypted

$ mkdir docx_x && unzip -o -q 沃德.docx -d docx_x
$ grep -n 'color w:val="FFFFFF"' docx_x/word/document.xml   # 白字隐藏
$ grep -n 'w:vanish'             docx_x/word/document.xml   # 隐藏文字
```

docx 结构取证：17 个 ZIP 条目、CRC 全通过、无注释/尾随数据；`document.xml.rels` 只引用
styles/settings/theme/fontTable/customizations，**无** `embeddings`/`media`/activeX/customXml，
正文也没有 object/pict/hyperlink/altChunk/OLE/drawing —— 线索只在文本本身。

PDF 结构取证：9 页、80 对象、未加密、无 EmbeddedFile/Filespec/JavaScript/Launch/URI/AA/OpenAction、
无元数据流、无尾随数据；页面文本均为正常渲染（无 `Tr 3`、无白色/页外文本）——纯结构看不到明文。

ZIP 结构：单条目 `皮皮特.pptx`（未压缩 104,515 B，deflate 30,624 B，CRC32 `e584cba3`）；
general-purpose flag `0x0001` + method 8 = **传统 ZipCrypto**（非 AES）；文件名字节
`c6 a4 c6 a4 cc d8 2e 70 70 74 78` 为 **GBK** 编码的“皮皮特”。

## 3. 漏洞分析（四层链式编码）

### 3.1 第一层 沃德.docx —— 两处隐藏文字

全文 157 段 / 84 run，正文是中文散文诗，唯一异常是两个隐藏 run：

```xml
<!-- P018：白色字体隐藏（白字白底不可见） -->
<w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>password1:True_lOve_</w:t></w:r>

<!-- P155：w:vanish 隐藏文字（默认不显示、不打印） -->
<w:r><w:rPr><w:vanish/><w:sz w:val="21"/></w:rPr><w:t>password12:i2_supReMe</w:t></w:r>
```

`password1` / `password12` 的编号 1 和 12 是烟雾弹：不存在中间编号密码，
**两个值直接首尾拼接**才是下一层钥匙。

### 3.2 第二层 皮迪符.pdf —— wbStego4open 位平面隐写

用拼接后的口令 `True_lOve_i2_supReMe` 通过 **wbStego4open** 的 Decode/Extract 从 PDF 提取，
得到下一层 ZIP 口令：

```
工具：wbStego4open（open 版）
载体：皮迪符.pdf
密码：True_lOve_i2_supReMe
提取结果：this_is_pAssw0rd@!
```

wbStego 把数据嵌到位平面冗余位里，所以纯结构分析看不到任何明文。

### 3.3 第三层 皮皮特的外套.zip —— ZipCrypto 解密

用第二层口令解出 `皮皮特.pptx`（CRC 校验通过）。

### 3.4 第四层 皮皮特.pptx —— 七进制颜色编码

76 页幻灯片，每页一张纯色图，`slideN.xml` 里图片的 `descr` 属性即颜色名：

```xml
<pic:cNvPr id="2" name="Picture 1" descr="yellow.png"/>
```

7 种颜色 = 七进制 0–6，`while`（出题人把 white 拼错）是分隔符：

| 颜色 | red | orange | yellow | green | cyan | blue | purple |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 七进制 | 0 | 1 | 2 | 3 | 4 | 5 | 6 |

每段分隔区间内是七进制数 → 转十进制 → ASCII。

## 4. 关键中间值

| 名称 | 值 |
| --- | --- |
| docx 隐藏文本 1 | `password1:True_lOve_` |
| docx 隐藏文本 2 | `password12:i2_supReMe` |
| PDF 隐写口令（拼接） | `True_lOve_i2_supReMe` |
| PDF 提取结果 | `this_is_pAssw0rd@!` |
| ZIP 加密算法 | 传统 ZipCrypto（口令 = `this_is_pAssw0rd@!`） |
| ZIP 条目名编码 | GBK（`c6 a4 c6 a4 cc d8 …` = 皮皮特） |
| pptx 页数 | 76 |
| 颜色→七进制 | red0 orange1 yellow2 green3 cyan4 blue5 purple6 |
| 分隔符 | `while`（=white 拼错） |
| Flag | `flag{10ve_exCe1_!!!}` |

## 5. 攻击链

```
沃德.docx ──w:color=FFFFFF 白字 / w:vanish 隐藏文字──▶ True_lOve_ + i2_supReMe
                                                          │ 直接拼接
                                                          ▼
                                              True_lOve_i2_supReMe
                                                          │ wbStego4open Extract
皮迪符.pdf ◀──────────────────────────────────────────────┘
    │  this_is_pAssw0rd@!
    ▼
皮皮特的外套.zip ──ZipCrypto 解密──▶ 皮皮特.pptx (76 slides)
    │  每页 descr=颜色名
    ▼
颜色名 ──▶ 七进制数字 ──▶ 十进制 ──▶ ASCII
    ▼
flag{10ve_exCe1_!!!}
```

## 6. 完整脚本

`exploits/office_love_chain.py`：

```python
#!/usr/bin/env python3
"""办公室爱情 全链复现：zip -> pptx -> 七进制颜色 -> flag
用法: python office_love_chain.py [皮皮特的外套.zip]
前置: 已从 docx/PDF 得到 ZipCrypto 口令 this_is_pAssw0rd@!
"""
import re, os, sys, zipfile, subprocess

zip_path = sys.argv[1] if len(sys.argv) > 1 else '皮皮特的外套.zip'
pptx_password = b'this_is_pAssw0rd@!'

# 1) 解 ZIP 得到 pptx
z = zipfile.ZipFile(zip_path)
data = z.read(z.namelist()[0], pwd=pptx_password)   # CRC 校验通过
open('/tmp/pipite.pptx', 'wb').write(data)

# 2) 展开 pptx
os.makedirs('/tmp/pptx_x', exist_ok=True)
subprocess.run(['unzip', '-o', '-q', '/tmp/pipite.pptx', '-d', '/tmp/pptx_x'], check=True)

# 3) 每页 descr=颜色名 -> 七进制 -> 十进制 -> ASCII
cmap = {'red': 0, 'orange': 1, 'yellow': 2, 'green': 3, 'cyan': 4, 'blue': 5, 'purple': 6}
groups, cur = [], []
for i in range(1, 77):
    s = open(f'/tmp/pptx_x/ppt/slides/slide{i}.xml').read()
    name = re.findall(r'descr="([^"]+)"', s)[0].replace('.png', '')
    if name in ('while', 'white'):
        groups.append(cur); cur = []
    else:
        cur.append(cmap[name])
if cur:
    groups.append(cur)

out = ''
for g in groups:
    v = 0
    for d in g:
        v = v * 7 + d
    out += chr(v)
print('FLAG:', out)
```

运行：

```bash
.venv/bin/python exploits/office_love_chain.py challenges/misc1/皮皮特的外套.zip
```

## 7. 实际输出

```text
$ .venv/bin/python exploits/office_love_chain.py challenges/misc1/皮皮特的外套.zip
FLAG: flag{10ve_exCe1_!!!}
```

七进制解码表（20 组，全部吻合）：

| 组 | 颜色序列 | 七进制 | 十进制 | 字符 |
| --- | --- | --- | --- | --- |
| 1 | yellow red cyan | 204₇ | 102 | `f` |
| 2 | yellow orange green | 213₇ | 108 | `l` |
| 3 | orange purple purple | 166₇ | 97 | `a` |
| 4 | yellow red blue | 205₇ | 103 | `g` |
| 5 | yellow green cyan | 234₇ | 123 | `{` |
| 6 | orange red red | 100₇ | 49 | `1` |
| 7 | purple purple | 66₇ | 48 | `0` |
| 8 | yellow yellow purple | 226₇ | 118 | `v` |
| 9 | yellow red green | 203₇ | 101 | `e` |
| 10 | orange purple cyan | 164₇ | 95 | `_` |
| 11 | yellow red green | 203₇ | 101 | `e` |
| 12 | yellow green orange | 231₇ | 120 | `x` |
| 13 | orange yellow cyan | 124₇ | 67 | `C` |
| 14 | yellow red green | 203₇ | 101 | `e` |
| 15 | orange red red | 100₇ | 49 | `1` |
| 16 | orange purple cyan | 164₇ | 95 | `_` |
| 17 | cyan blue | 45₇ | 33 | `!` |
| 18 | cyan blue | 45₇ | 33 | `!` |
| 19 | cyan blue | 45₇ | 33 | `!` |
| 20 | yellow green purple | 236₇ | 125 | `}` |

## 8. 踩坑记录

- **“找 password2~11”陷阱**：docx 隐藏文本编号 1 和 12 是烟雾弹，不存在中间编号；两值**直接拼接**才是钥匙。
- **docx 藏附件**：17 条目 + 全部 rels + document.xml 标签枚举，确认无 embeddings/media/activeX/customXml。
- **元数据藏线索**：core/app/custom 属性、ZIP 注释、extra field、统一 DOS 时间均排查，只得到 WPS 遥测指纹（`hdid`），无下一层指示。
- **拿 True_lOve_ / i2_supReMe 直接爆 ZIP**：两口令的所有编码字节形式（ASCII/UTF-8/GBK/GB18030/Latin-1/UTF-16LE/BE/BOM）、大小写变体、两种顺序拼接，全部过不了 ZipCrypto CRC —— 反证 ZIP 口令必来自 PDF 层。
- **PDF 纯结构找明文**：80 对象、9 页流、字体、JPEG 及注释、文本渲染属性全部排查无载荷 —— wbStego 是位平面级隐写，必须用工具 + 正确口令才能提取。

## 9. 验证

- 三份附件 SHA256 与题目信息一致；`file` 类型与结构取证吻合。
- ZIP 解密后 CRC32 `e584cba3` 校验通过，pptx 为合法 OOXML。
- 最终 flag 由本机脚本端到端复跑确认（20 组七进制解码全部吻合），非转述。
- 平台提交：本环境接受原样 `flag{10ve_exCe1_!!!}`；NSSCTF 复现版提交需用 `NSSCTF{10ve_exCe1_!!!}`。

> 说明：中间环节「拼接口令 → wbStego4open 提取 PDF → 得到 `this_is_pAssw0rd@!`」的思路定位参考了公开 WP（长城杯 2022 政企组原题，NSSCTF 复现）以跳出 password2~11 陷阱；所得口令已在本机实测可解 ZIP，最终 flag 由本机脚本复跑确认。
