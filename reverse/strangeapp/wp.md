---
title: "strangeApp"
ctf: "湾区杯 2025"
date: 2026-09-20
category: reverse
difficulty: medium
flag_format: "flag{...}"
author: ""
---

# strangeApp

## Summary

这是一个 Android 脱壳与 DEX 指令还原题。APK 使用 `ProxyApplication` 加载
`libshell.so`，并将 `assets/extract.dat` 传入 native 层。`extract.dat` 保存被抽取的
DEX `code_item` 指令，恢复后可以得到真正的校验逻辑。

## Solution

### 1. 分析 APK 结构

APK 的 Manifest 将 Application 指向：

```text
com.swdd.shell.ProxyApplication
```

`ProxyApplication.onCreate()` 的关键流程是：

```java
System.loadLibrary("shell");
JniBridge.setData(readAllBytes(getAssets().open("extract.dat")));
loadDex();
```

静态反编译 `classes.dex` 后，`MainActivity` 的方法体只有大量 `nop`，说明真正的
指令已被抽出。

### 2. 还原 `extract.dat`

通过分析 `setData()` 可知，文件由多条记录组成：

```text
uint32 code_off
uint32 opcode_units
uint8  opcode[opcode_units * 2]
```

例如第一条记录：

```text
18 EF 3B 00 08 00 00 00
70 10 27 AF 00 00 5B 01 22 73 5B 02 23 73 0E 00
```

其中 `code_off = 0x003BEF18`，指令长度为 `8 * 2 = 16` 字节，末尾的 `0E 00`
是 Dalvik 的 `return-void`。

将每条记录的 opcode 回填到 `classes.dex` 对应的 `code_item`，并修复 DEX 的
SHA-1 与 Adler32 校验和后，再用 JADX/JEB 反编译即可恢复 `MainActivity`。

### 3. 恢复加密逻辑并解密

恢复后的核心代码如下：

```java
String key = "1234567891123456";
String iv = "1234567891123456";

SecretKeySpec secretKey = new SecretKeySpec(
    key.getBytes(StandardCharsets.UTF_8),
    a("DES")
);

Cipher cipher = Cipher.getInstance(a("DES/CBC/PKCS5Padding"));
```

函数 `a()` 会将算法名称的第一个字符与 `5` 异或：

```java
char changed = (char)(algo.charAt(0) ^ 5);
```

因此：

```text
'D' ^ 5 = 'A'
```

实际算法为 `AES/CBC/PKCS5Padding`，而不是 DES。

`TARGET` 是 48 字节密文：

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = b"1234567891123456"
IV = b"1234567891123456"
TARGET = bytes.fromhex(
    "7611077c9d331785b217cb012a6db305"
    "a90ab36a4e647b8ad11f13387397f5da"
    "eeb80c2a113787d477d757765fb4ac45"
)

plain = AES.new(KEY, AES.MODE_CBC, IV).decrypt(TARGET)
print(unpad(plain, AES.block_size).decode())
```

输出：

```text
flag{just_easy_strange_app_right?}
```

## Flag

```text
flag{just_easy_strange_app_right?}
```
