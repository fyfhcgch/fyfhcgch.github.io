---
layout: post
title: "Java 反射机制入门：从正射、类加载到动态代理（零基础手把手版）"
date: 2026-07-20 10:00:00 +0800
author: Security Researcher
categories: [Java, 编程基础]
tags: [Java, 反射, 正射, 类加载机制, ClassLoader, 动态代理, JDK代理, AOP]
description: 面向零基础新人的 Java 反射机制教程，从普通方法调用（正射）讲起，逐步理解 Class 对象、构造方法、成员变量、方法调用、类加载机制以及 Java 动态代理。
---

## 前言：为什么要学反射？

很多新人第一次听到“反射”时，会觉得它很玄：

> 程序运行起来以后，居然还能知道一个类有哪些字段、哪些方法，甚至还能创建对象、调用方法？

没错，这就是 Java 反射最核心的能力。

如果你以后学习这些内容，几乎都会碰到反射：

- Spring / Spring Boot：自动创建对象、依赖注入、AOP；
- MyBatis / Hibernate：把数据库字段映射成 Java 对象；
- JUnit：自动识别 `@Test` 方法并执行；
- Lombok、Jackson、Fastjson：读取字段、注解、构造对象；
- Java 动态代理：运行时生成代理对象，实现日志、鉴权、事务等增强逻辑。

本文从最普通的“正射”开始，一步步讲清楚：

1. 什么是正射；
2. 什么是反射；
3. `Class` 对象到底是什么；
4. 如何用反射创建对象、调用方法、操作字段；
5. Java 类加载机制是怎么回事；
6. Java 动态代理为什么离不开反射。

---

## 一、先讲“正射”：普通写法就是正射

“正射”不是 Java 官方特别常用的术语。为了方便理解，我们可以把它理解为：

> 编译时就知道要创建哪个类、调用哪个方法，然后直接写代码调用。

比如下面这个例子：

```java
class User {
    private String name;

    public User(String name) {
        this.name = name;
    }

    public void sayHello() {
        System.out.println("你好，我是 " + name);
    }
}

public class Main {
    public static void main(String[] args) {
        User user = new User("小明");
        user.sayHello();
    }
}
```

这就是最常见的 Java 写法：

```java
User user = new User("小明");
user.sayHello();
```

它的特点是：

| 特点 | 说明 |
|---|---|
| 类名写死 | 代码里明确写了 `User` |
| 方法名写死 | 代码里明确写了 `sayHello()` |
| 编译期确定 | 编译器能检查这个类和方法是否存在 |
| 性能好 | JVM 可以直接优化普通方法调用 |

这种写法简单、直接、类型安全，是日常开发中最推荐的默认写法。

### 那为什么还需要反射？

因为有些场景下，程序在“编译时”并不知道要用哪个类。

举个例子：

假设你写了一个框架，这个框架需要根据配置文件创建对象。

配置文件里写着：

```properties
className=com.example.UserService
```

程序运行时才读到这个字符串：

```java
String className = "com.example.UserService";
```

问题来了：

你只有一个字符串，怎么创建 `com.example.UserService` 的对象？

普通正射写法需要这样：

```java
UserService service = new UserService();
```

但现在类名是运行时才知道的字符串，代码里没有办法提前写死。这时候就需要反射。

---

## 二、反射是什么：让程序在运行时“照镜子”

反射的英文是 Reflection，直译就是“反射”。

可以这样理解：

> 一个 Java 类在运行时可以像照镜子一样，看见自己的构造方法、字段、方法、注解等信息，并且程序还可以操作这些信息。

普通写法：

```java
User user = new User("小明");
user.sayHello();
```

反射写法：

```java
Class<?> clazz = Class.forName("User");
Object user = clazz.getConstructor(String.class).newInstance("小明");
clazz.getMethod("sayHello").invoke(user);
```

你会发现：

- 正射：直接写 `new User()`；
- 反射：通过 `Class` 对象找到构造方法，再创建对象；
- 正射：直接写 `user.sayHello()`；
- 反射：通过方法名字符串 `sayHello` 找到方法，再执行。

所以反射的关键变化是：

> 原来写在代码里的类名、方法名，现在可以变成运行时的字符串。

这就是很多框架“灵活”的根本原因。

---

## 三、理解反射之前，先理解 `Class` 对象

在 Java 里，我们平时写的类，比如：

```java
class User {
    private String name;
    public void sayHello() {}
}
```

编译后会变成一个 `.class` 文件。

程序运行时，JVM 会把这个 `.class` 文件加载进内存，并为它创建一个特殊对象：

```java
java.lang.Class
```

这个 `Class` 对象里面保存了这个类的结构信息，例如：

- 类名；
- 包名；
- 父类；
- 实现了哪些接口；
- 有哪些构造方法；
- 有哪些字段；
- 有哪些方法；
- 有哪些注解。

可以把 `Class` 对象理解为一份“类的说明书”。

### 对象和 Class 对象的关系

很多新人会混淆“对象”和“Class 对象”。

看下面这段代码：

```java
User u1 = new User("小明");
User u2 = new User("小红");
```

这里有两个普通对象：

```text
u1 -> User 对象，小明
u2 -> User 对象，小红
```

但是它们对应的类信息只有一份：

```text
User.class -> 描述 User 这个类的 Class 对象
```

也就是说：

```java
System.out.println(u1.getClass() == u2.getClass()); // true
```

两个不同的 `User` 对象，共用同一个 `User.class` 类信息。

---

## 四、获取 Class 对象的三种常见方式

准备一个类：

```java
package demo;

public class User {
    private String name;
    private int age;

    public User() {
    }

    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public void sayHello() {
        System.out.println("你好，我是 " + name + "，今年 " + age + " 岁");
    }
}
```

### 方式一：类名 `.class`

```java
Class<User> clazz = User.class;
```

适合你在写代码时已经知道类名的情况。

### 方式二：对象 `.getClass()`

```java
User user = new User("小明", 18);
Class<?> clazz = user.getClass();
```

适合你手里已经有对象，想反查它属于哪个类。

### 方式三：`Class.forName("完整类名")`

```java
Class<?> clazz = Class.forName("demo.User");
```

适合类名来自配置文件、数据库、网络请求等运行时数据的情况。

这一种在框架里非常常见。

### 三种方式对比

| 方式 | 示例 | 适用场景 |
|---|---|---|
| `类名.class` | `User.class` | 编译时知道类 |
| `对象.getClass()` | `user.getClass()` | 已经有对象 |
| `Class.forName()` | `Class.forName("demo.User")` | 运行时根据字符串加载类 |

---

## 五、反射创建对象：从 `new` 到 `newInstance`

正射创建对象：

```java
User user = new User("小明", 18);
```

反射创建对象需要两步：

1. 获取 `Class` 对象；
2. 获取构造方法并调用。

### 调用无参构造方法

```java
Class<?> clazz = Class.forName("demo.User");
Object obj = clazz.getDeclaredConstructor().newInstance();
System.out.println(obj);
```

解释一下：

```java
clazz.getDeclaredConstructor()
```

表示获取无参构造方法。

```java
newInstance()
```

表示通过这个构造方法创建对象。

### 调用有参构造方法

```java
Class<?> clazz = Class.forName("demo.User");

Object obj = clazz
        .getDeclaredConstructor(String.class, int.class)
        .newInstance("小明", 18);
```

这里的：

```java
String.class, int.class
```

表示构造方法的参数类型。

因为一个类可能有多个构造方法：

```java
public User() {}
public User(String name) {}
public User(String name, int age) {}
```

所以 Java 必须知道你要找的是哪一个构造方法。

---

## 六、反射调用方法：从 `obj.method()` 到 `method.invoke()`

正射调用方法：

```java
user.sayHello();
```

反射调用方法：

```java
Class<?> clazz = Class.forName("demo.User");
Object user = clazz
        .getDeclaredConstructor(String.class, int.class)
        .newInstance("小明", 18);

Method method = clazz.getDeclaredMethod("sayHello");
method.invoke(user);
```

完整导包：

```java
import java.lang.reflect.Method;
```

### 调用带参数的方法

假设 `User` 类中有这样一个方法：

```java
public void study(String subject, int hours) {
    System.out.println(name + " 学习 " + subject + "，学习了 " + hours + " 小时");
}
```

反射调用：

```java
Method method = clazz.getDeclaredMethod("study", String.class, int.class);
method.invoke(user, "Java", 3);
```

这里分两步：

```java
clazz.getDeclaredMethod("study", String.class, int.class)
```

表示找到 `study(String, int)` 这个方法。

```java
method.invoke(user, "Java", 3)
```

表示在 `user` 这个对象上执行该方法，并传入参数 `"Java"` 和 `3`。

### 调用有返回值的方法

假设有方法：

```java
public String getInfo() {
    return name + ":" + age;
}
```

反射调用：

```java
Method method = clazz.getDeclaredMethod("getInfo");
Object result = method.invoke(user);
System.out.println(result);
```

`invoke()` 的返回值类型是 `Object`，如果你知道真实类型，可以强转：

```java
String info = (String) method.invoke(user);
```

---

## 七、反射操作字段：读取和修改成员变量

假设有这个类：

```java
package demo;

public class User {
    private String name;
    private int age;

    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

`name` 是 `private`，普通代码在类外部不能直接访问：

```java
// user.name = "小红"; // 编译报错
```

但反射可以先拿到字段对象：

```java
import java.lang.reflect.Field;

Class<?> clazz = Class.forName("demo.User");
Object user = clazz
        .getDeclaredConstructor(String.class, int.class)
        .newInstance("小明", 18);

Field nameField = clazz.getDeclaredField("name");
nameField.setAccessible(true);

nameField.set(user, "小红");
Object value = nameField.get(user);

System.out.println(value); // 小红
```

重点是这一句：

```java
nameField.setAccessible(true);
```

它表示取消 Java 语言层面的访问检查，让反射可以访问 `private` 字段。

> 注意：在 Java 9 之后引入模块系统，如果跨模块强行访问内部成员，可能还会受到模块边界限制。日常学习和普通项目中，先理解 `setAccessible(true)` 的基本作用即可。

---

## 八、`getMethod` 和 `getDeclaredMethod` 有什么区别？

反射 API 里经常能看到两组名字：

```java
getMethod()
getDeclaredMethod()

getField()
getDeclaredField()

getConstructor()
getDeclaredConstructor()
```

它们的区别可以这样记：

| 方法 | 能拿到什么 |
|---|---|
| `getMethod` | 当前类和父类中的 `public` 方法 |
| `getDeclaredMethod` | 当前类中声明的方法，包括 `private`，但不包含父类 |
| `getField` | 当前类和父类中的 `public` 字段 |
| `getDeclaredField` | 当前类中声明的字段，包括 `private`，但不包含父类 |
| `getConstructor` | 当前类中的 `public` 构造方法 |
| `getDeclaredConstructor` | 当前类中的所有构造方法，包括 `private` |

简单记忆：

- 不带 `Declared`：更关注 `public`，并且可能会往父类找；
- 带 `Declared`：只看当前类自己声明了什么，但可以看到 `private`。

---

## 九、一个完整反射示例：复制即可运行

把下面代码保存为 `ReflectionDemo.java`：

```java
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

class Student {
    private String name;
    private int age;

    public Student() {
        this.name = "默认学生";
        this.age = 0;
    }

    public Student(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public void sayHello() {
        System.out.println("大家好，我是 " + name + "，今年 " + age + " 岁");
    }

    public String study(String subject) {
        return name + " 正在学习 " + subject;
    }
}

public class ReflectionDemo {
    public static void main(String[] args) throws Exception {
        // 1. 获取 Class 对象
        Class<?> clazz = Class.forName("Student");

        // 2. 获取有参构造方法并创建对象
        Constructor<?> constructor = clazz.getDeclaredConstructor(String.class, int.class);
        Object student = constructor.newInstance("小明", 18);

        // 3. 调用普通方法
        Method sayHello = clazz.getDeclaredMethod("sayHello");
        sayHello.invoke(student);

        // 4. 调用有参数、有返回值的方法
        Method study = clazz.getDeclaredMethod("study", String.class);
        Object result = study.invoke(student, "Java 反射");
        System.out.println(result);

        // 5. 修改 private 字段
        Field nameField = clazz.getDeclaredField("name");
        nameField.setAccessible(true);
        nameField.set(student, "小红");

        // 6. 再次调用方法，观察 name 是否改变
        sayHello.invoke(student);
    }
}
```

运行：

```bash
javac ReflectionDemo.java
java ReflectionDemo
```

输出类似：

```text
大家好，我是 小明，今年 18 岁
小明 正在学习 Java 反射
大家好，我是 小红，今年 18 岁
```

这段代码覆盖了反射最常用的三件事：

1. 创建对象；
2. 调用方法；
3. 修改字段。

---

## 十、类加载机制：类是怎么进入 JVM 的？

理解反射离不开类加载。

Java 代码从 `.java` 到运行，大致经历：

```text
User.java  --javac-->  User.class  --ClassLoader-->  JVM 内存中的 Class 对象
```

也就是说：

- `.java` 是源代码；
- `.class` 是字节码文件；
- `ClassLoader` 负责把 `.class` 加载进 JVM；
- JVM 为这个类创建一个 `Class` 对象；
- 反射就是围绕这个 `Class` 对象展开操作。

### 类加载的三个大阶段

Java 类加载通常分为：

```text
加载 Loading -> 连接 Linking -> 初始化 Initialization
```

其中连接又可以细分为：

```text
验证 Verification -> 准备 Preparation -> 解析 Resolution
```

整体如下：

```text
加载
  ↓
连接
  ├─ 验证：检查 class 文件是否合法、安全
  ├─ 准备：为 static 变量分配内存并设置默认值
  └─ 解析：把符号引用转换成直接引用
  ↓
初始化：执行 static 变量赋值和 static 代码块
```

### 阶段一：加载

加载阶段主要做三件事：

1. 通过类的全限定名找到 `.class` 文件；
2. 读取 `.class` 文件的字节流；
3. 在 JVM 中生成对应的 `Class` 对象。

比如：

```java
Class<?> clazz = Class.forName("demo.User");
```

这行代码会触发 JVM 去寻找并加载 `demo.User`。

### 阶段二：连接

连接阶段是 JVM 对类进行检查和准备。

#### 1. 验证

检查 `.class` 文件是否符合 JVM 规范。

例如：

- 文件格式是否正确；
- 字节码指令是否安全；
- 类型转换是否合法；
- 是否破坏 JVM 运行规则。

#### 2. 准备

给类变量，也就是 `static` 变量分配内存，并设置默认值。

比如：

```java
public class Demo {
    static int count = 10;
}
```

准备阶段时：

```java
count = 0;
```

初始化阶段时才会执行：

```java
count = 10;
```

很多新人会误以为准备阶段就赋值为 `10`，其实不是。

#### 3. 解析

把常量池里的符号引用转换为可以直接定位的引用。

通俗理解就是：

> 原来只是记录“我要调用某个类的某个方法”，解析后 JVM 能更直接地找到它。

### 阶段三：初始化

初始化阶段会执行：

- `static` 变量的显式赋值；
- `static` 代码块。

例如：

```java
class InitDemo {
    static int count = 10;

    static {
        System.out.println("InitDemo 初始化了");
    }
}
```

当类真正初始化时，会输出：

```text
InitDemo 初始化了
```

---

## 十一、什么时候会触发类初始化？

下面这些情况通常会触发类初始化：

### 1. 创建对象

```java
new User();
```

### 2. 访问类的静态变量

```java
System.out.println(User.count);
```

### 3. 调用类的静态方法

```java
User.print();
```

### 4. 使用 `Class.forName()`

```java
Class.forName("demo.User");
```

默认情况下，`Class.forName()` 会触发类初始化。

### 5. 初始化子类时，父类会先初始化

```java
class Parent {
    static {
        System.out.println("Parent 初始化");
    }
}

class Child extends Parent {
    static {
        System.out.println("Child 初始化");
    }
}

new Child();
```

输出顺序：

```text
Parent 初始化
Child 初始化
```

### 不容易触发初始化的情况

下面这些情况需要特别注意：

```java
Class<?> c = User.class;
```

获取类字面量通常不会触发初始化。

```java
ClassLoader.getSystemClassLoader().loadClass("demo.User");
```

`loadClass()` 通常只加载类，不主动初始化类。

```java
System.out.println(User.CONSTANT);
```

如果 `CONSTANT` 是编译期常量，也可能不会触发 `User` 初始化。

例如：

```java
public static final String CONSTANT = "hello";
```

因为这个值可能在编译阶段就被放进调用方的常量池了。

---

## 十二、ClassLoader：是谁把类加载进来的？

`ClassLoader` 就是类加载器。

它的职责是：

> 根据类名找到字节码，然后把字节码加载到 JVM 中。

常见类加载器：

| 类加载器 | 主要负责 |
|---|---|
| Bootstrap ClassLoader | 加载 Java 核心类库，例如 `java.lang.String` |
| Platform ClassLoader | 加载平台相关类库，Java 8 中常被称为 Extension ClassLoader |
| Application ClassLoader | 加载应用程序 classpath 下的类 |
| Custom ClassLoader | 用户自定义类加载器 |

可以打印看一下：

```java
public class ClassLoaderDemo {
    public static void main(String[] args) {
        System.out.println(String.class.getClassLoader());
        System.out.println(ClassLoaderDemo.class.getClassLoader());
        System.out.println(ClassLoaderDemo.class.getClassLoader().getParent());
    }
}
```

可能输出：

```text
null
jdk.internal.loader.ClassLoaders$AppClassLoader@xxxx
jdk.internal.loader.ClassLoaders$PlatformClassLoader@xxxx
```

为什么 `String.class.getClassLoader()` 是 `null`？

因为 `String` 由 Bootstrap ClassLoader 加载，这个加载器是 JVM 内部实现的，在 Java 代码里通常用 `null` 表示。

---

## 十三、双亲委派模型：先问父加载器

Java 类加载有一个重要机制：双亲委派模型。

通俗说就是：

> 一个类加载器想加载类时，先不急着自己加载，而是先交给父加载器；父加载器加载不了，自己才尝试加载。

流程大概是：

```text
Application ClassLoader
        ↓ 先委托
Platform ClassLoader
        ↓ 先委托
Bootstrap ClassLoader
        ↓ 加载不了再往回
Platform ClassLoader
        ↓ 加载不了再往回
Application ClassLoader
```

### 为什么要这样设计？

主要有两个好处。

#### 1. 防止核心类被篡改

假设你自己写一个类：

```java
package java.lang;

public class String {
}
```

如果没有双亲委派，程序可能加载你写的假 `String`，整个 Java 基础都会乱套。

有了双亲委派，`java.lang.String` 会优先交给 Bootstrap ClassLoader 加载，保证核心类的稳定。

#### 2. 避免类重复加载

同一个类如果被多个加载器重复加载，可能会出现类型不一致的问题。

在 Java 中，判断一个类是不是同一个类，不只看类名，还要看加载它的类加载器。

也就是说：

```text
类的唯一身份 = 全限定类名 + 加载它的 ClassLoader
```

这也是很多中间件、插件系统、热部署框架里容易出现 ClassCastException 的原因之一。

---

## 十四、反射和类加载有什么关系？

一句话总结：

> 反射依赖 `Class` 对象，而 `Class` 对象来自类加载。

比如：

```java
Class<?> clazz = Class.forName("demo.User");
```

这行代码背后至少包含两层含义：

1. 如果 `demo.User` 还没有被加载，JVM 会先加载它；
2. 加载完成后，JVM 返回描述这个类的 `Class` 对象；
3. 你拿到 `Class` 对象后，就能继续获取字段、方法、构造器。

因此学习顺序可以是：

```text
普通调用 -> Class 对象 -> 反射 API -> 类加载机制 -> 动态代理/框架原理
```

---

## 十五、动态代理是什么？先从静态代理说起

代理这个词并不神秘。

生活中有很多代理：

- 房东不直接出租，交给中介代理；
- 明星不直接谈商务，交给经纪人代理；
- 你不直接访问目标对象，而是先访问代理对象。

在程序里，代理对象通常用来做增强逻辑，比如：

- 方法执行前打印日志；
- 方法执行后统计耗时；
- 方法执行前检查权限；
- 方法执行异常时记录错误；
- 方法执行前开启事务，执行后提交事务。

### 先看普通接口和实现类

```java
interface UserService {
    void addUser(String name);
}

class UserServiceImpl implements UserService {
    @Override
    public void addUser(String name) {
        System.out.println("添加用户：" + name);
    }
}
```

正射调用：

```java
UserService userService = new UserServiceImpl();
userService.addUser("小明");
```

### 静态代理写法

如果想在 `addUser` 前后加日志，可以写一个代理类：

```java
class UserServiceStaticProxy implements UserService {
    private final UserService target;

    public UserServiceStaticProxy(UserService target) {
        this.target = target;
    }

    @Override
    public void addUser(String name) {
        System.out.println("[日志] addUser 开始");
        target.addUser(name);
        System.out.println("[日志] addUser 结束");
    }
}
```

使用：

```java
UserService target = new UserServiceImpl();
UserService proxy = new UserServiceStaticProxy(target);
proxy.addUser("小明");
```

输出：

```text
[日志] addUser 开始
添加用户：小明
[日志] addUser 结束
```

静态代理的问题是：

> 每个接口都要手写一个代理类，类一多就很麻烦。

如果有 `OrderService`、`ProductService`、`PayService`，就要写一堆代理类。

这时候动态代理就有用了。

---

## 十六、JDK 动态代理：运行时生成代理对象

JDK 自带动态代理，核心类是：

```java
java.lang.reflect.Proxy
java.lang.reflect.InvocationHandler
```

它可以在程序运行时生成一个代理对象，不需要你手写代理类。

### 完整示例：复制即可运行

保存为 `JdkProxyDemo.java`：

```java
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

interface UserService {
    void addUser(String name);
    void deleteUser(String name);
}

class UserServiceImpl implements UserService {
    @Override
    public void addUser(String name) {
        System.out.println("真正执行：添加用户 " + name);
    }

    @Override
    public void deleteUser(String name) {
        System.out.println("真正执行：删除用户 " + name);
    }
}

class LogInvocationHandler implements InvocationHandler {
    private final Object target;

    public LogInvocationHandler(Object target) {
        this.target = target;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        System.out.println("[日志] 方法开始：" + method.getName());

        Object result = method.invoke(target, args);

        System.out.println("[日志] 方法结束：" + method.getName());
        return result;
    }
}

public class JdkProxyDemo {
    public static void main(String[] args) {
        // 1. 真实对象
        UserService target = new UserServiceImpl();

        // 2. 创建代理对象
        UserService proxy = (UserService) Proxy.newProxyInstance(
                target.getClass().getClassLoader(),
                target.getClass().getInterfaces(),
                new LogInvocationHandler(target)
        );

        // 3. 调用代理对象的方法
        proxy.addUser("小明");
        proxy.deleteUser("小红");
    }
}
```

运行：

```bash
javac JdkProxyDemo.java
java JdkProxyDemo
```

输出类似：

```text
[日志] 方法开始：addUser
真正执行：添加用户 小明
[日志] 方法结束：addUser
[日志] 方法开始：deleteUser
真正执行：删除用户 小红
[日志] 方法结束：deleteUser
```

---

## 十七、逐行拆解 JDK 动态代理

最核心的代码是：

```java
UserService proxy = (UserService) Proxy.newProxyInstance(
        target.getClass().getClassLoader(),
        target.getClass().getInterfaces(),
        new LogInvocationHandler(target)
);
```

`Proxy.newProxyInstance()` 需要三个参数。

### 参数一：类加载器

```java
target.getClass().getClassLoader()
```

代理类也是一个类，既然是类，就需要类加载器加载。

这里通常使用目标对象的类加载器。

### 参数二：接口数组

```java
target.getClass().getInterfaces()
```

JDK 动态代理要求目标类至少实现一个接口。

比如：

```java
class UserServiceImpl implements UserService
```

代理对象会实现同样的接口，所以可以强转成：

```java
UserService proxy
```

### 参数三：调用处理器

```java
new LogInvocationHandler(target)
```

`InvocationHandler` 决定了：

> 当别人调用代理对象的方法时，实际执行什么逻辑。

它只有一个核心方法：

```java
public Object invoke(Object proxy, Method method, Object[] args) throws Throwable
```

三个参数分别是：

| 参数 | 含义 |
|---|---|
| `proxy` | 生成出来的代理对象本身 |
| `method` | 当前被调用的方法 |
| `args` | 当前方法的参数 |

当你写：

```java
proxy.addUser("小明");
```

真实流程其实是：

```text
调用代理对象 addUser
        ↓
进入 InvocationHandler.invoke()
        ↓
打印方法开始日志
        ↓
method.invoke(target, args) 调用真实对象
        ↓
打印方法结束日志
```

所以动态代理的本质是：

> JVM 运行时生成一个实现了接口的代理类，然后所有方法调用都会转发到 `InvocationHandler.invoke()`。

---

## 十八、动态代理为什么和反射有关？

看这一行：

```java
Object result = method.invoke(target, args);
```

这里的 `method` 是 `java.lang.reflect.Method` 对象。

也就是说，动态代理接收到方法调用后，并不是直接写死：

```java
target.addUser("小明");
```

而是通过反射调用：

```java
method.invoke(target, args);
```

这就让代理逻辑可以统一处理所有方法：

```java
addUser()
deleteUser()
updateUser()
queryUser()
```

不管调用哪个方法，都会先进同一个 `invoke()` 方法。

这也是 AOP 的基础思想。

---

## 十九、一个更像实际项目的代理：统计方法耗时

很多项目都会统计方法耗时。用动态代理可以这样写：

```java
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

interface OrderService {
    void createOrder(String productName);
}

class OrderServiceImpl implements OrderService {
    @Override
    public void createOrder(String productName) {
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        System.out.println("创建订单：" + productName);
    }
}

class TimeCostHandler implements InvocationHandler {
    private final Object target;

    public TimeCostHandler(Object target) {
        this.target = target;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        long start = System.currentTimeMillis();
        try {
            return method.invoke(target, args);
        } finally {
            long end = System.currentTimeMillis();
            System.out.println(method.getName() + " 耗时：" + (end - start) + " ms");
        }
    }
}

public class TimeProxyDemo {
    public static void main(String[] args) {
        OrderService target = new OrderServiceImpl();

        OrderService proxy = (OrderService) Proxy.newProxyInstance(
                target.getClass().getClassLoader(),
                target.getClass().getInterfaces(),
                new TimeCostHandler(target)
        );

        proxy.createOrder("机械键盘");
    }
}
```

这类思想在 Spring AOP 中非常常见。

比如：

- 方法执行前开启事务；
- 方法执行成功后提交事务；
- 方法执行异常时回滚事务。

伪代码大概是：

```java
try {
    开启事务();
    Object result = method.invoke(target, args);
    提交事务();
    return result;
} catch (Exception e) {
    回滚事务();
    throw e;
}
```

---

## 二十、JDK 动态代理和 CGLIB 的区别

Java 里常见代理方式有两类：

| 代理方式 | 特点 |
|---|---|
| JDK 动态代理 | Java 官方提供，要求目标类实现接口 |
| CGLIB 动态代理 | 通过生成目标类的子类实现代理，不强制要求接口 |

简单理解：

### JDK 动态代理

要求有接口：

```java
interface UserService {}
class UserServiceImpl implements UserService {}
```

生成的代理对象大致相当于：

```java
class $Proxy0 implements UserService {
    // 方法调用交给 InvocationHandler
}
```

### CGLIB 动态代理

不要求接口，它通过继承目标类生成子类。

大致相当于：

```java
class UserServiceImpl$$EnhancerByCGLIB extends UserServiceImpl {
    // 重写方法，加入增强逻辑
}
```

所以 CGLIB 对 `final` 类、`final` 方法有限制，因为 final 不能被继承或重写。

Spring 中经常会根据情况选择代理方式：

- 有接口时，可以使用 JDK 动态代理；
- 没有接口时，可以使用 CGLIB；
- 具体行为还会受到 Spring 版本和配置影响。

---

## 二十一、反射、类加载、动态代理三者关系图

可以用下面这张文字图来理解：

```text
.java 源码
   ↓ javac 编译
.class 字节码
   ↓ ClassLoader 加载
Class 对象
   ↓ 反射 API
Constructor / Field / Method
   ↓
创建对象 / 访问字段 / 调用方法
   ↓
动态代理把 Method 调用统一交给 InvocationHandler
```

三者关系一句话：

> 类加载负责把类带进 JVM，反射负责运行时操作类信息，动态代理利用反射和运行时生成类的能力来增强方法调用。

---

## 二十二、反射的优点和缺点

### 优点

#### 1. 灵活

可以在运行时根据字符串创建对象、调用方法。

```java
Class.forName("com.example.UserService")
```

#### 2. 适合写框架

框架不知道你将来会写哪些类，但可以通过反射扫描、创建和调用。

比如 Spring 可以通过反射创建：

```java
UserController
UserService
UserRepository
```

#### 3. 可以操作注解

例如：

```java
@Service
public class UserService {}
```

框架可以通过反射发现这个类上有 `@Service` 注解，然后把它注册为 Bean。

### 缺点

#### 1. 可读性较差

普通代码：

```java
user.sayHello();
```

反射代码：

```java
clazz.getDeclaredMethod("sayHello").invoke(user);
```

明显反射更绕。

#### 2. 编译期检查变弱

普通代码如果方法名写错，编译器会报错。

反射代码方法名是字符串：

```java
getDeclaredMethod("sayHelo")
```

少写一个 `l`，编译器发现不了，运行时才会报错。

#### 3. 性能通常低于直接调用

反射调用需要额外检查和分派，通常比普通方法调用慢。

不过在大多数业务系统里，反射不是主要性能瓶颈。框架也会通过缓存 `Class`、`Method`、`Constructor` 等方式减少开销。

#### 4. 可能破坏封装

`setAccessible(true)` 可以访问私有字段和方法，如果滥用，会让代码维护成本变高。

---

## 二十三、学习反射最常见的报错

### 1. `ClassNotFoundException`

```text
java.lang.ClassNotFoundException: demo.User
```

含义：找不到类。

常见原因：

- 类名没有写完整包名；
- classpath 配置不正确；
- 依赖 jar 没有引入；
- 类文件没有编译出来。

### 2. `NoSuchMethodException`

```text
java.lang.NoSuchMethodException
```

含义：找不到方法或构造方法。

常见原因：

- 方法名写错；
- 参数类型写错；
- `int.class` 和 `Integer.class` 搞混；
- 用了 `getMethod()` 找 `private` 方法。

### 3. `IllegalAccessException`

含义：访问权限不够。

处理方式通常是：

```java
method.setAccessible(true);
field.setAccessible(true);
constructor.setAccessible(true);
```

### 4. `InvocationTargetException`

含义：被反射调用的方法内部抛出了异常。

例如：

```java
method.invoke(user);
```

如果 `user` 的方法内部抛异常，外层可能会包一层 `InvocationTargetException`。

可以这样取出真实异常：

```java
try {
    method.invoke(user);
} catch (InvocationTargetException e) {
    Throwable realException = e.getCause();
    realException.printStackTrace();
}
```

---

## 二十四、手写一个极简“框架”：根据类名创建对象并调用方法

下面这个例子模拟框架根据配置运行代码。

保存为 `MiniFrameworkDemo.java`：

```java
import java.lang.reflect.Method;

class HelloTask {
    public void run() {
        System.out.println("HelloTask 正在运行");
    }
}

class ByeTask {
    public void run() {
        System.out.println("ByeTask 正在运行");
    }
}

public class MiniFrameworkDemo {
    public static void main(String[] args) throws Exception {
        // 假设这两个值来自配置文件
        String className = "HelloTask";
        String methodName = "run";

        Class<?> clazz = Class.forName(className);
        Object obj = clazz.getDeclaredConstructor().newInstance();
        Method method = clazz.getDeclaredMethod(methodName);
        method.invoke(obj);
    }
}
```

如果把：

```java
String className = "HelloTask";
```

改成：

```java
String className = "ByeTask";
```

不用改主流程代码，就可以执行另一个类。

这就是反射带来的灵活性。

很多框架的底层思想也是类似的，只是实际项目中会更复杂：

- 扫描 classpath；
- 查找带注解的类；
- 创建对象；
- 管理对象生命周期；
- 处理依赖关系；
- 通过代理增强方法。

---

## 二十五、最终总结

如果你是零基础新人，可以按下面这条线理解：

### 1. 正射

普通写法，编译时确定类和方法。

```java
User user = new User();
user.sayHello();
```

### 2. 反射

运行时通过 `Class` 对象操作类。

```java
Class<?> clazz = Class.forName("User");
Object obj = clazz.getDeclaredConstructor().newInstance();
clazz.getDeclaredMethod("sayHello").invoke(obj);
```

### 3. 类加载

JVM 通过 `ClassLoader` 把 `.class` 文件加载进内存，并生成 `Class` 对象。

```text
.class -> ClassLoader -> Class 对象
```

### 4. 动态代理

运行时生成代理对象，把方法调用统一交给 `InvocationHandler`。

```java
Proxy.newProxyInstance(classLoader, interfaces, invocationHandler)
```

### 5. 它们之间的关系

```text
类加载产生 Class 对象
反射操作 Class 对象
动态代理利用反射统一增强方法调用
```

学会这些之后，再去看 Spring 的 IOC、AOP、MyBatis 的对象映射、JUnit 的测试执行机制，就会轻松很多。

---

## 推荐练习

建议按顺序完成下面几个小练习：

1. 写一个 `Person` 类，用正射创建对象并调用方法；
2. 用 `Class.forName()` 获取 `Person` 的 `Class` 对象；
3. 用反射调用 `Person` 的无参构造方法；
4. 用反射调用 `Person` 的有参构造方法；
5. 用反射修改 `private name` 字段；
6. 用反射调用一个带参数、有返回值的方法；
7. 写一个接口 `UserService` 和实现类 `UserServiceImpl`；
8. 先写静态代理；
9. 再用 JDK 动态代理实现日志增强；
10. 在 `InvocationHandler` 中统计方法耗时。

只要你能独立敲完这些练习，Java 反射、类加载、动态代理的入门关就基本过了。
