## 漏洞点

程序将正确输入设计为 21×21 迷宫中的移动路径（`h/j/k/l`）。迷宫数据可从二进制常量表恢复；其开放格构成一棵树，因此 `(0,0)` 到 `(20,20)` 存在唯一 134 步路径。最终 Flag 不是路径本身，而是题目要求的 `hashlib.md5(path.encode()).hexdigest()`。

另有长度为 16 的线性校验分支，解得 `flag{fake__flag}`，程序提示其为错误路径，属于干扰。

## 利用步骤

1. 检查 PE 字符串与反汇编，确认程序提示为 `flag{md5(input)}`，并识别移动字符 `h/j/k/l`。

2. 从迷宫校验数据恢复 21×21 网格，并对开放格做 BFS：

```python
# 开放格满足：
# byte_table[idx] ^ dword_table[idx] ^ (col << 8) ^ row == 1
```

3. 得到 `(0,0)` 到 `(20,20)` 的唯一 134 步路径：

```text
jjjllllllllllllllljjjjjjjjkjjkkkkhhhhhhhkkkkkkkkkkjjjjllljjjlllhhhhlljjjjjjkkkkkkkkjjlllllllllllhhlllllhhhlhhhhhhhhlljjjjjjjjjjjjjjjjl
```

4. 按题意计算 MD5：

```python
import hashlib

path = "jjjllllllllllllllljjjjjjjjkjjkkkkhhhhhhhkkkkkkkkkkjjjjllljjjlllhhhhlljjjjjjkkkkkkkkjjlllllllllllhhlllllhhhlhhhhhhhhlljjjjjjjjjjjjjjjjl"
print(hashlib.md5(path.encode()).hexdigest())
```

输出：

```text
54735c379e641a51ffac016a263bf6be
```

## Flag

```text
flag{54735c379e641a51ffac016a263bf6be}
```

Flag 来自二进制中恢复的唯一迷宫路径，经 `hashlib.md5(path.encode()).hexdigest()` 计算得到。