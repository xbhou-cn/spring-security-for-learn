### 简单集成Spring Security

**Authentication（认证）** 和 **Authorization（授权，也叫访问控制）**

**认证：** 系统认为用户是否能登陆

**授权：** 系统判定用户是否有权限做某事

Spring Security是重量级框架，各方面功能比较全面，还有一种常用的轻量级安全框架shiro，常用的安全管理技术栈的组合是这样的：

SSM+Shiro
Spring Boot/Spring Cloud +Spring Security

#### 第一步：引入依赖
~~~xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
~~~

#### 第二步：编写测试类
~~~java
@RestController
@RequestMapping("/test")
public class TestController {
    @GetMapping("/test")
    public String test() {
        return "SUCCESS";
    }
}
~~~
#### 第三步：访问/test/test
![](https://md-image-xbhou.oss-cn-beijing.aliyuncs.com/QQ%E5%9B%BE%E7%89%8720210615235733.png?Expires=1623807517&OSSAccessKeyId=TMP.3Kjam4UtGSt3tX9G9MANvVLgC26WdeHYz5hKJi32JV3dAC5w1kWVBijMuQYNvRoPNzB8nWaLHE9phaBQgCtLee48WoktEP&Signature=qlPMbYtRvQgYSDHWoyjLmFet1Yo%3D&versionId=CAEQDRiBgMC04MnB0BciIDMzMjQwNjhjZGYxOTQ5YzhiMWIyMDY2YzM0ZTk5ZGQ2&response-content-type=application%2Foctet-stream)

**注意：**

* 默认用户：user
* 默认密码：控制台打印的内容 - Using generated security password: **1df479b1-dea6-4302-9678-1954d4527a23**