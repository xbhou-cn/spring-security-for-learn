### UserDetailsService接口讲解: 查询数据库用户名和密码的过程

1. 创建类继承UsernamePasswordAuthenticationFilter，并重写attemptAuthentication，successfulAuthentication，unsuccessfulAuthentication
2. 创建类实现UserDetailsService接口讲解，编写查询数据库的逻辑，返回User(org.springframework.security.core.userdetails)对象

### PasswordEncoder接口讲解: 提供加密方式对密码进行加密，用于返回User对象里面的密码加密

**BCryptPasswordEncoder**是SpringSecurity官方推荐的的密码解析器

~~~java
package xb.hou;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @title: BCryptPasswordEncoderTest
 * @Author xbhou
 * @Date: 2021-06-17 13:08
 * @Version 1.0
 */
public class BCryptPasswordEncoderTest {
    @Test
    public void test01() {
        // 创建密码解析器
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        // 对密码进行加密
        String xbhou = encoder.encode("xbhou");
        System.out.println("加密后的数据：" + xbhou);
        System.out.println("判断原字符串和加密之前是否匹配：" + encoder.matches("xbhou", xbhou));
    }
}

~~~

### 认证

#### 设置登陆的用户名和密码

1. 通配置文件(application.yml)

~~~yml
spring:
  security:
    user:
      name: xbhou
      password: 123456
~~~

2. 通过配置类

**注意：**

1. configure(WebSecurity) 配置Security的filter链

2. configure(HttpSecurity) 配置如何通过连接器的保护

3. configure(AuthenticationManagerBuilder) 配置user-detail服务

~~~java
package xb.hou.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @title: SecurityConfig1
 * @Author xbhou
 * @Date: 2021-06-17 13:23
 * @Version 1.0
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    final private PasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("xbhou").password(passwordEncoder.encode("123456")).roles("admin");
    }
}

~~~

**注意：** 使用该方法之前要先把PasswordEncoder创建出

~~~java
package xb.hou;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@Configuration
public class AppRun {

    public static void main(String[] args) {
        SpringApplication.run(AppRun.class, args);
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

~~~

3. 自定义编写实现类

~~~
   1. 创建配置类，指定使用哪一个UserDetailsService的实现类
~~~

~~~java
package xb.hou.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    final private PasswordEncoder passwordEncoder;
    final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }
}
~~~

    2. 编写实现类，返回User对象

~~~java
package xb.hou.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    final private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        // TODO 可以在此处查数据库等操作，通过登录名进行查询获取用户，security自动比对密码是否正确
        return new User("xbhou", passwordEncoder.encode("123456"), AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}

~~~
