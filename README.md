## Sa-Token 反序列化

## 项目地址

[Sa-Token: 开源、免费、轻量级 Java 权限认证框架，让鉴权变得简单、优雅！—— 登录认证、权限认证、分布式Session会话、微服务网关鉴权、SSO 单点登录、OAuth2.0 统一认证](https://gitee.com/dromara/sa-token)

[dromara/Sa-Token: 一个轻量级 Java 权限认证框架，让鉴权变得简单、优雅！—— 登录认证、权限认证、分布式Session会话、微服务网关鉴权、单点登录、OAuth2.0](https://github.com/dromara/sa-token)



## 漏洞摘要

<=1.44.0

类型: 不安全反序列化（CWE-502）
组件: Sa-Token JDK/Base64 序列化模板在反序列化环节未做类型/过滤控制，ObjectInputStream 直接读取任意对象，若持久层字符串值可由攻击者控制且类路径包含可利用 gadget（如 Commons-Collections 3.x），可导致任意代码执行。
触发面: 当启用 JDK 序列化模板并从外部存储取回字符串后经 Base64 解码 → JDK 反序列化。
默认影响: 默认 JSON 模板不受影响；仅在显式启用 JDK/Base64 模板时受影响。

## 漏洞成因概述

Sa-Token 在 Token-Session 读取路径中：
- 从外部可控介质（Cookie/Header/Body）读取 token
- 基于 token 拼接 Session Key
- 从 SaTokenDao 中读取字符串
- 使用 JDK 原生反序列化将字符串反序列化为对象
- 未对反序列化类型进行任何白名单/黑名单校验

导致攻击者可构造恶意序列化数据，在 `ObjectInputStream.readObject()` 阶段触发 Gadget 链执行任意代码。

## 受影响代码：
- JDK 反序列化入口（无类型过滤）: SaSerializerTemplateForJdk.java
- Base64 包装模板（启用后走上面的反序列化路径）: SaSerializerTemplateForJdkUseBase64.java
- DAO 将 String 与 Object 互转，反序列化由全局模板决定: SaTokenDaoByObjectFollowString.java
- Token-Session 访问路径（用于触发读取）: StpLogic.java:1480-1510, StpLogic.java


## 利用链


### 用户可控 Token 输入点

* 攻击者通过 HTTP 请求携带 **Cookie 中的 token**
* 条件：

  ```java
  SaTokenConfig#setIsReadCookie(true)
  ```

代码路径（逻辑等价）：

```
HTTP Cookie → SaHolder.getRequest() → getTokenValue()
```

---

### Token → Token-Session Key 映射

Sa-Token 使用 token 构造 Token-Session 存储键：

```
token
  ↓
splicingKeyTokenSession(token)
  ↓
如：satoken:token-session:test
```

此 key **完全由攻击者控制的 token 决定**

---

### SaTokenDao 返回恶意字符串

当使用：

```java
SaTokenDaoByObjectFollowString
```

时：

* DAO 存储的是 **String**
* 读取 Session 时：

    * 自动触发 **String → Object 的反序列化**

攻击者只需让 DAO 中对应 key 的 value 为：

```
Base64(JDK Serialized Object)
```

---

### 触发 JDK 原生反序列化

调用路径核心点：

```
StpLogic.getTokenSession()
  ↓
SaSession.create()
  ↓
SaManager.getSaSerializerTemplate().stringToObject()
  ↓
ObjectInputStream.readObject()
```

此处 **无任何类型检查 / 安全过滤**

---

### Gadget 链执行
若类路径中存在可利用 Gadget（如 commons-collections 3.x）：
* 恶意对象在 `readObject()` 阶段触发 Gadget 链
最终实现 **任意命令执行（RCE）**
这里我拿cc来跑

