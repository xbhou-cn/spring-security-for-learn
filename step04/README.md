### Spring Security 学习

#### 记住密码

**流程**
![image](https://user-images.githubusercontent.com/47892921/123993979-84a18d80-d9ff-11eb-9b95-40d4418276f7.png)

1. 首次认证的源码解析

~~~java
package org.springframework.security.web.authentication;

...

public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean implements ApplicationEventPublisherAware, MessageSourceAware {
    protected ApplicationEventPublisher eventPublisher;
    protected AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private AuthenticationManager authenticationManager;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private RememberMeServices rememberMeServices = new NullRememberMeServices();
    private RequestMatcher requiresAuthenticationRequestMatcher;
    private boolean continueChainBeforeSuccessfulAuthentication = false;
    private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();
    private boolean allowSessionCreation = true;
    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

    ...

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if (!this.requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
        } else {
            if (this.logger.isDebugEnabled()) {
                this.logger.debug("Request is to process authentication");
            }
            // 认证方法
            ...
            // 认证通过后调用该方法
            this.successfulAuthentication(request, response, chain, authResult);
        }
    }
    ...

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Authentication success. Updating SecurityContextHolder to contain: " + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);
        // 认证成功，将token写入数据库
        this.rememberMeServices.loginSuccess(request, response, authResult);
        if (this.eventPublisher != null) {
            this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }

        this.successHandler.onAuthenticationSuccess(request, response, authResult);
    }
    ...
}
~~~

~~~java
...

public abstract class AbstractRememberMeServices implements RememberMeServices, InitializingBean, LogoutHandler {
    public static final String SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY = "remember-me";
    public static final String DEFAULT_PARAMETER = "remember-me";
    public static final int TWO_WEEKS_S = 1209600;
    private static final String DELIMITER = ":";
    protected final Log logger = LogFactory.getLog(this.getClass());
    protected final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private UserDetailsService userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private String cookieName = "remember-me";
    private String cookieDomain;
    private String parameter = "remember-me";
    private boolean alwaysRemember;
    private String key;
    private int tokenValiditySeconds = 1209600;
    private Boolean useSecureCookie = null;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    protected AbstractRememberMeServices(String key, UserDetailsService userDetailsService) {
        Assert.hasLength(key, "key cannot be empty or null");
        Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
        this.key = key;
        this.userDetailsService = userDetailsService;
    }

    public final void loginFail(HttpServletRequest request, HttpServletResponse response) {
        this.logger.debug("Interactive login attempt was unsuccessful.");
        this.cancelCookie(request, response);
        this.onLoginFail(request, response);
    }

    protected void onLoginFail(HttpServletRequest request, HttpServletResponse response) {
    }

    public final void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
        if (!this.rememberMeRequested(request, this.parameter)) {
            this.logger.debug("Remember-me login not requested.");
        } else {
            // 到达这一步，继续向下执行，到PersistentTokenBasedRememberMeServices
            this.onLoginSuccess(request, response, successfulAuthentication);
        }
    }

    protected abstract void onLoginSuccess(HttpServletRequest var1, HttpServletResponse var2, Authentication var3);
}
~~~

~~~java
...

public class PersistentTokenBasedRememberMeServices extends AbstractRememberMeServices {
    private PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();
    private SecureRandom random = new SecureRandom();
    public static final int DEFAULT_SERIES_LENGTH = 16;
    public static final int DEFAULT_TOKEN_LENGTH = 16;
    private int seriesLength = 16;
    private int tokenLength = 16;

    public PersistentTokenBasedRememberMeServices(String key, UserDetailsService userDetailsService, PersistentTokenRepository tokenRepository) {
        super(key, userDetailsService);
        this.tokenRepository = tokenRepository;
    }

    protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response) {
        if (cookieTokens.length != 2) {
            throw new InvalidCookieException("Cookie token did not contain 2 tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
        } else {
            String presentedSeries = cookieTokens[0];
            String presentedToken = cookieTokens[1];
            PersistentRememberMeToken token = this.tokenRepository.getTokenForSeries(presentedSeries);
            if (token == null) {
                throw new RememberMeAuthenticationException("No persistent token found for series id: " + presentedSeries);
            } else if (!presentedToken.equals(token.getTokenValue())) {
                this.tokenRepository.removeUserTokens(token.getUsername());
                throw new CookieTheftException(this.messages.getMessage("PersistentTokenBasedRememberMeServices.cookieStolen", "Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
            } else if (token.getDate().getTime() + (long) this.getTokenValiditySeconds() * 1000L < System.currentTimeMillis()) {
                throw new RememberMeAuthenticationException("Remember-me login has expired");
            } else {
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug("Refreshing persistent login token for user '" + token.getUsername() + "', series '" + token.getSeries() + "'");
                }

                PersistentRememberMeToken newToken = new PersistentRememberMeToken(token.getUsername(), token.getSeries(), this.generateTokenData(), new Date());

                try {
                    this.tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(), newToken.getDate());
                    this.addCookie(newToken, request, response);
                } catch (Exception var9) {
                    this.logger.error("Failed to update token: ", var9);
                    throw new RememberMeAuthenticationException("Autologin failed due to data access problem");
                }

                return this.getUserDetailsService().loadUserByUsername(token.getUsername());
            }
        }
    }

    protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
        String username = successfulAuthentication.getName();
        this.logger.debug("Creating new persistent login for user " + username);
        PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(username, this.generateSeriesData(), this.generateTokenData(), new Date());

        try {
            // 通过PersistentTokenRepository创建token，存入数据库
            // 因此，想要把token存入数据库，则需要实例化JdbcTokenRepositoryImpl，设置DataSource
            this.tokenRepository.createNewToken(persistentToken);
            this.addCookie(persistentToken, request, response);
        } catch (Exception var7) {
            this.logger.error("Failed to save persistent token ", var7);
        }
    }
    ...
}
~~~

2. 实现UserDetailsService，并配置用户登陆查询方式

* 实现UserDetailsService

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
    final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return new User("admin", passwordEncoder.encode("admin"), AuthorityUtils.commaSeparatedStringToAuthorityList("user:list"));
    }
}

~~~

* 指定用户登陆的查询方式

~~~java
package xb.hou.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

/**
 * @title: SecurityConfig
 * @Author xbhou
 * @Date: 2021-06-17 13:23
 * @Version 1.0
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    final private PasswordEncoder passwordEncoder;
    final private UserDetailsService userDetailsService;
    final private PersistentTokenRepository repository;

    /**
     * 重写该方法，并指定用户查询实现方式
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //配置退出
        http.logout().logoutUrl("/logout").logoutSuccessUrl("/user/logout").permitAll();
        // 没有权限跳转到unauth.html
        http.exceptionHandling().accessDeniedPage("/unauth.html");
        // 登陆方式
        http.formLogin().loginPage("/login.html") //登陆画面
                .loginProcessingUrl("/user/login") //登陆的form的action
                .defaultSuccessUrl("/success.html").permitAll() // 登陆成功后跳转的画面
                .and().authorizeRequests().anyRequest().authenticated() // 其他访问需要认证，以及授权
                .and().rememberMe().tokenRepository(repository) // token记录方式
                .tokenValiditySeconds(3600) // 过期时间，单位为秒
                .and().csrf().disable();
    }
}

~~~
* login.html
~~~html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登陆</title>
</head>
<body>
<!--请求方式必须是post，请求地址要和配置的地址相同-->
<form action="/user/login" method="post">
    <!--用户名和密码输入框的name必须是username和password-->
    用户名：<input type="text" name="username"/>
    <br/>
    密码：<input type="password" name="password"/>
    <br/>
    <div>
        <!--自动登陆的name必须是remember-me-->
        <label><input type="checkbox" name="remember-me"/>自动登录</label>
        <button type="submit">立即登陆</button>
    </div>
</form>
</body>
</html>
~~~
* success.html
~~~html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登陆成功</title>
</head>
<body>
<a href="/logout">退出</a>
</body>
</html>
~~~
* unauth.html

~~~html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>错误</title>
</head>
<body>
<h1>没有访问权限！</h1>
</body>
</html>
~~~

3. 配置数据库连接，实例化JdbcTokenRepositoryImpl，设置DataSource

* 数据库配置信息

~~~yml
server:
  port: 8000

#配置数据源
spring:
  main:
    allow-bean-definition-overriding: true
  #配置 Jpa
  jpa:
    hibernate:
      ddl-auto: update
    properties:
      dialect: org.hibernate.dialect.MySQL5Dialect
    open-in-view: true
  datasource:
    druid:
      db-type: com.alibaba.druid.pool.DruidDataSource
      driverClassName: com.mysql.cj.jdbc.Driver
      url: jdbc:mysql://localhost/demo?serverTimezone=Asia/Shanghai&characterEncoding=utf8&useSSL=false&allowPublicKeyRetrieval=true
      username: root
      password: root
      # 初始连接数
      initial-size: 5
      # 最小连接数
      min-idle: 15
      # 最大连接数
      max-active: 30
      # 超时时间(以秒数为单位)
      remove-abandoned-timeout: 180
      # 获取连接超时时间
      max-wait: 3000
      # 连接有效性检测时间
      time-between-eviction-runs-millis: 60000
      # 连接在池中最小生存的时间
      min-evictable-idle-time-millis: 300000
      # 连接在池中最大生存的时间
      max-evictable-idle-time-millis: 900000
      # 指明连接是否被空闲连接回收器(如果有)进行检验.如果检测失败,则连接将被从池中去除
      test-while-idle: true
      # 指明是否在从池中取出连接前进行检验,如果检验失败, 则从池中去除连接并尝试取出另一个
      test-on-borrow: true
      # 是否在归还到池中前进行检验
      test-on-return: false
      # 检测连接是否有效
      validation-query: select 1
~~~

* 实例化JdbcTokenRepositoryImpl，设置DataSource
    * 使用JdbcTokenRepositoryImpl需要先建表，或者setCreateTableOnStartup为true
    ~~~sql
        CREATE TABLE persistent_logins (
        username VARCHAR ( 64 ) NOT NULL,
        series VARCHAR ( 64 ) PRIMARY KEY,
        token VARCHAR ( 64 ) NOT NULL,
        last_used TIMESTAMP NOT NULL)
    ~~~
~~~java
package xb.hou.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * @title: BeanConfig
 * @Author xbhou
 * @Date: 2021-06-24 16:40
 * @Version 1.0
 */
@Configuration
@RequiredArgsConstructor
public class BeanConfig {
    final private DataSource dataSource;

    /**
     * 实例化JdbcTokenRepositoryImpl，设置DataSource
     * @return
     */
    @Bean
    public PersistentTokenRepository getRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }

    /**
     * 加密方式
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
~~~
4. 记住密码再次登陆时，源码解析
* RememberMeAuthenticationFilter
~~~java
package org.springframework.security.web.authentication.rememberme;

...
public class RememberMeAuthenticationFilter extends GenericFilterBean implements ApplicationEventPublisherAware {
    private ApplicationEventPublisher eventPublisher;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationManager authenticationManager;
    private RememberMeServices rememberMeServices;

    public RememberMeAuthenticationFilter(AuthenticationManager authenticationManager, RememberMeServices rememberMeServices) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(rememberMeServices, "rememberMeServices cannot be null");
        this.authenticationManager = authenticationManager;
        this.rememberMeServices = rememberMeServices;
    }

    public void afterPropertiesSet() {
        Assert.notNull(this.authenticationManager, "authenticationManager must be specified");
        Assert.notNull(this.rememberMeServices, "rememberMeServices must be specified");
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            // 调用rememberMeServices的autoLogin方法进行登陆，进入autoLogin方法
            Authentication rememberMeAuth = this.rememberMeServices.autoLogin(request, response);
            if (rememberMeAuth != null) {
                try {
                    rememberMeAuth = this.authenticationManager.authenticate(rememberMeAuth);
                    SecurityContextHolder.getContext().setAuthentication(rememberMeAuth);
                    this.onSuccessfulAuthentication(request, response, rememberMeAuth);
                    if (this.logger.isDebugEnabled()) {
                        this.logger.debug("SecurityContextHolder populated with remember-me token: '" + SecurityContextHolder.getContext().getAuthentication() + "'");
                    }

                    if (this.eventPublisher != null) {
                        this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(SecurityContextHolder.getContext().getAuthentication(), this.getClass()));
                    }

                    if (this.successHandler != null) {
                        this.successHandler.onAuthenticationSuccess(request, response, rememberMeAuth);
                        return;
                    }
                } catch (AuthenticationException var8) {
                    if (this.logger.isDebugEnabled()) {
                        this.logger.debug("SecurityContextHolder not populated with remember-me token, as AuthenticationManager rejected Authentication returned by RememberMeServices: '" + rememberMeAuth + "'; invalidating remember-me token", var8);
                    }

                    this.rememberMeServices.loginFail(request, response);
                    this.onUnsuccessfulAuthentication(request, response, var8);
                }
            }

            chain.doFilter(request, response);
        } else {
            if (this.logger.isDebugEnabled()) {
                this.logger.debug("SecurityContextHolder not populated with remember-me token, as it already contained: '" + SecurityContextHolder.getContext().getAuthentication() + "'");
            }

            chain.doFilter(request, response);
        }

    }

    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) {
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
    }

    public RememberMeServices getRememberMeServices() {
        return this.rememberMeServices;
    }
}
~~~
* AbstractRememberMeServices
~~~java
package org.springframework.security.web.authentication.rememberme;

public abstract class AbstractRememberMeServices implements RememberMeServices, InitializingBean, LogoutHandler {
    public static final String SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY = "remember-me";
    public static final String DEFAULT_PARAMETER = "remember-me";
    public static final int TWO_WEEKS_S = 1209600;
    private static final String DELIMITER = ":";
    protected final Log logger = LogFactory.getLog(this.getClass());
    protected final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private UserDetailsService userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private String cookieName = "remember-me";
    private String cookieDomain;
    private String parameter = "remember-me";
    private boolean alwaysRemember;
    private String key;
    private int tokenValiditySeconds = 1209600;
    private Boolean useSecureCookie = null;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    protected AbstractRememberMeServices(String key, UserDetailsService userDetailsService) {
        Assert.hasLength(key, "key cannot be empty or null");
        Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
        this.key = key;
        this.userDetailsService = userDetailsService;
    }

    public void afterPropertiesSet() {
        Assert.hasLength(this.key, "key cannot be empty or null");
        Assert.notNull(this.userDetailsService, "A UserDetailsService is required");
    }

    /**
     * 自动登陆方法
     * @param request
     * @param response
     * @return
     */
    public final Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
        // 获得cookie
        String rememberMeCookie = this.extractRememberMeCookie(request);
        if (rememberMeCookie == null) {
            return null;
        } else {
            this.logger.debug("Remember-me cookie detected");
            if (rememberMeCookie.length() == 0) {
                this.logger.debug("Cookie was empty");
                this.cancelCookie(request, response);
                return null;
            } else {
                UserDetails user = null;

                try {
                    // 对cookie解密
                    String[] cookieTokens = this.decodeCookie(rememberMeCookie);
                    // 通过cookie获取用户
                    user = this.processAutoLoginCookie(cookieTokens, request, response);
                    // 验证用户
                    this.userDetailsChecker.check(user);
                    this.logger.debug("Remember-me cookie accepted");
                    // 
                    return this.createSuccessfulAuthentication(request, user);
                } catch (CookieTheftException var6) {
                    this.cancelCookie(request, response);
                    throw var6;
                } catch (UsernameNotFoundException var7) {
                    this.logger.debug("Remember-me login was valid but corresponding user not found.", var7);
                } catch (InvalidCookieException var8) {
                    this.logger.debug("Invalid remember-me cookie: " + var8.getMessage());
                } catch (AccountStatusException var9) {
                    this.logger.debug("Invalid UserDetails: " + var9.getMessage());
                } catch (RememberMeAuthenticationException var10) {
                    this.logger.debug(var10.getMessage());
                }

                this.cancelCookie(request, response);
                return null;
            }
        }
    }

    ...

    protected abstract UserDetails processAutoLoginCookie(String[] var1, HttpServletRequest var2, HttpServletResponse var3) throws RememberMeAuthenticationException, UsernameNotFoundException;

    ...
}
~~~
* PersistentTokenBasedRememberMeServices
~~~java
package org.springframework.security.web.authentication.rememberme;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

public class PersistentTokenBasedRememberMeServices extends AbstractRememberMeServices {
    private PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();
    private SecureRandom random = new SecureRandom();
    public static final int DEFAULT_SERIES_LENGTH = 16;
    public static final int DEFAULT_TOKEN_LENGTH = 16;
    private int seriesLength = 16;
    private int tokenLength = 16;

    public PersistentTokenBasedRememberMeServices(String key, UserDetailsService userDetailsService, PersistentTokenRepository tokenRepository) {
        super(key, userDetailsService);
        this.tokenRepository = tokenRepository;
    }

    protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response) {
        if (cookieTokens.length != 2) {
            throw new InvalidCookieException("Cookie token did not contain 2 tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
        } else {
            String presentedSeries = cookieTokens[0];
            String presentedToken = cookieTokens[1];
            // 从数据库查询token信息
            PersistentRememberMeToken token = this.tokenRepository.getTokenForSeries(presentedSeries);
            if (token == null) {
                throw new RememberMeAuthenticationException("No persistent token found for series id: " + presentedSeries);
            } else if (!presentedToken.equals(token.getTokenValue())) {
                this.tokenRepository.removeUserTokens(token.getUsername());
                throw new CookieTheftException(this.messages.getMessage("PersistentTokenBasedRememberMeServices.cookieStolen", "Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
            } else if (token.getDate().getTime() + (long)this.getTokenValiditySeconds() * 1000L < System.currentTimeMillis()) {
                throw new RememberMeAuthenticationException("Remember-me login has expired");
            } else {
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug("Refreshing persistent login token for user '" + token.getUsername() + "', series '" + token.getSeries() + "'");
                }

                // 每次登陆更新数据库
                PersistentRememberMeToken newToken = new PersistentRememberMeToken(token.getUsername(), token.getSeries(), this.generateTokenData(), new Date());

                try {
                    this.tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(), newToken.getDate());
                    this.addCookie(newToken, request, response);
                } catch (Exception var9) {
                    this.logger.error("Failed to update token: ", var9);
                    throw new RememberMeAuthenticationException("Autologin failed due to data access problem");
                }

                // 通过UserDetailsService获取用户
                return this.getUserDetailsService().loadUserByUsername(token.getUsername());
            }
        }
    }
    ...
}

~~~
