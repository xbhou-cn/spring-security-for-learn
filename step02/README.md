### 简单集成Spring Security

**Authentication（认证）** 和 **Authorization（授权，也叫访问控制）**

**认证：** 系统认为用户是否能登陆

**授权：** 系统判定用户是否有权限做某事

Spring Security是重量级框架，各方面功能比较全面，还有一种常用的轻量级安全框架shiro，常用的安全管理技术栈的组合是这样的：

* SSM+Shiro
* Spring Boot/Spring Cloud +Spring Security

**核心模块：**

* Core - spring-security-core.jar

* Remoting - spring-security-remoting.jar

* Web - spring-security-web.jar

* Config - spring-security-config.jar

* LDAP - spring-security-ldap.jar

* OAuth 2.0 Core - spring-security-oauth2-core.jar

* OAuth 2.0 Client - spring-security-oauth2-client.jar

* OAuth 2.0 JOSE - spring-security-oauth2-jose.jar

* ACL - spring-security-acl.jar

* CAS - spring-security-cas.jar

* OpenID - spring-security-openid.jar

* Test - spring-security-test.jar

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
![](https://img-blog.csdnimg.cn/20210422225055759.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM5MjY2NjUy,size_16,color_FFFFFF,t_70)

**注意：**

* 默认用户：user
* 默认密码：控制台打印的内容 - Using generated security password: **1df479b1-dea6-4302-9678-1954d4527a23**

### 基本原理
**本质上是过滤器链**
#### FilterSecurityInterceptor:是一个方法级的权限过滤器，基本位于过滤链最底部
~~~java
package org.springframework.security.web.access.intercept;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;

public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {
    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private FilterInvocationSecurityMetadataSource securityMetadataSource;
    private boolean observeOncePerRequest = true;

    public FilterSecurityInterceptor() {
    }

    /**
     * 初始化
     * @param arg0
     */
    public void init(FilterConfig arg0) {
    }

    /**
     * 销毁
     */
    public void destroy() {
    }

    /**
     * 过滤方法
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        this.invoke(fi);
    }

    public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource newSource) {
        this.securityMetadataSource = newSource;
    }

    public Class<?> getSecureObjectClass() {
        return FilterInvocation.class;
    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        if (fi.getRequest() != null && fi.getRequest().getAttribute("__spring_security_filterSecurityInterceptor_filterApplied") != null && this.observeOncePerRequest) {
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            if (fi.getRequest() != null && this.observeOncePerRequest) {
                fi.getRequest().setAttribute("__spring_security_filterSecurityInterceptor_filterApplied", Boolean.TRUE);
            }

            InterceptorStatusToken token = super.beforeInvocation(fi);

            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, (Object)null);
        }

    }

    public boolean isObserveOncePerRequest() {
        return this.observeOncePerRequest;
    }

    public void setObserveOncePerRequest(boolean observeOncePerRequest) {
        this.observeOncePerRequest = observeOncePerRequest;
    }
}
~~~~
#### ExceptionTranslationFilter：是一个异常过滤器，用来处理在认证授权过程中抛出的异常
~~~java
package org.springframework.security.web.access;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

public class ExceptionTranslationFilter extends GenericFilterBean {
    private AccessDeniedHandler accessDeniedHandler;
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationTrustResolver authenticationTrustResolver;
    private ThrowableAnalyzer throwableAnalyzer;
    private RequestCache requestCache;
    private final MessageSourceAccessor messages;

    public ExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint) {
        this(authenticationEntryPoint, new HttpSessionRequestCache());
    }

    public ExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint, RequestCache requestCache) {
        this.accessDeniedHandler = new AccessDeniedHandlerImpl();
        this.authenticationTrustResolver = new AuthenticationTrustResolverImpl();
        this.throwableAnalyzer = new ExceptionTranslationFilter.DefaultThrowableAnalyzer();
        this.requestCache = new HttpSessionRequestCache();
        this.messages = SpringSecurityMessageSource.getAccessor();
        Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
        Assert.notNull(requestCache, "requestCache cannot be null");
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.requestCache = requestCache;
    }

    public void afterPropertiesSet() {
        Assert.notNull(this.authenticationEntryPoint, "authenticationEntryPoint must be specified");
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;

        try {
            // 放行方法
            chain.doFilter(request, response);
            this.logger.debug("Chain processed normally");
        } catch (IOException var9) {
            throw var9;
        } catch (Exception var10) {
            // catch异常进行处理
            Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(var10);
            RuntimeException ase = (AuthenticationException)this.throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);
            if (ase == null) {
                ase = (AccessDeniedException)this.throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
            }

            if (ase == null) {
                if (var10 instanceof ServletException) {
                    throw (ServletException)var10;
                }

                if (var10 instanceof RuntimeException) {
                    throw (RuntimeException)var10;
                }

                throw new RuntimeException(var10);
            }

            if (response.isCommitted()) {
                throw new ServletException("Unable to handle the Spring Security Exception because the response is already committed.", var10);
            }

            this.handleSpringSecurityException(request, response, chain, (RuntimeException)ase);
        }

    }

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return this.authenticationEntryPoint;
    }

    protected AuthenticationTrustResolver getAuthenticationTrustResolver() {
        return this.authenticationTrustResolver;
    }

    private void handleSpringSecurityException(HttpServletRequest request, HttpServletResponse response, FilterChain chain, RuntimeException exception) throws IOException, ServletException {
        if (exception instanceof AuthenticationException) {
            this.logger.debug("Authentication exception occurred; redirecting to authentication entry point", exception);
            this.sendStartAuthentication(request, response, chain, (AuthenticationException)exception);
        } else if (exception instanceof AccessDeniedException) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (!this.authenticationTrustResolver.isAnonymous(authentication) && !this.authenticationTrustResolver.isRememberMe(authentication)) {
                this.logger.debug("Access is denied (user is not anonymous); delegating to AccessDeniedHandler", exception);
                this.accessDeniedHandler.handle(request, response, (AccessDeniedException)exception);
            } else {
                this.logger.debug("Access is denied (user is " + (this.authenticationTrustResolver.isAnonymous(authentication) ? "anonymous" : "not fully authenticated") + "); redirecting to authentication entry point", exception);
                this.sendStartAuthentication(request, response, chain, new InsufficientAuthenticationException(this.messages.getMessage("ExceptionTranslationFilter.insufficientAuthentication", "Full authentication is required to access this resource")));
            }
        }

    }

    protected void sendStartAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, AuthenticationException reason) throws ServletException, IOException {
        SecurityContextHolder.getContext().setAuthentication((Authentication)null);
        this.requestCache.saveRequest(request, response);
        this.logger.debug("Calling Authentication entry point.");
        this.authenticationEntryPoint.commence(request, response, reason);
    }

    public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        Assert.notNull(accessDeniedHandler, "AccessDeniedHandler required");
        this.accessDeniedHandler = accessDeniedHandler;
    }

    public void setAuthenticationTrustResolver(AuthenticationTrustResolver authenticationTrustResolver) {
        Assert.notNull(authenticationTrustResolver, "authenticationTrustResolver must not be null");
        this.authenticationTrustResolver = authenticationTrustResolver;
    }

    public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
        Assert.notNull(throwableAnalyzer, "throwableAnalyzer must not be null");
        this.throwableAnalyzer = throwableAnalyzer;
    }

    private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {
        private DefaultThrowableAnalyzer() {
        }

        protected void initExtractorMap() {
            super.initExtractorMap();
            this.registerExtractor(ServletException.class, (throwable) -> {
                ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
                return ((ServletException)throwable).getRootCause();
            });
        }
    }
}
~~~

#### UsernamePasswordAuthenticationFilter：对/login的POST请求做拦截，校验表单中用户名，密码。

~~~java
package org.springframework.security.web.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";
    private String usernameParameter = "username";
    private String passwordParameter = "password";
    private boolean postOnly = true;

    public UsernamePasswordAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login", "POST"));
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            String username = this.obtainUsername(request);
            String password = this.obtainPassword(request);
            if (username == null) {
                username = "";
            }

            if (password == null) {
                password = "";
            }

            username = username.trim();
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
            this.setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }

    @Nullable
    protected String obtainPassword(HttpServletRequest request) {
        return request.getParameter(this.passwordParameter);
    }

    @Nullable
    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(this.usernameParameter);
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

    public void setUsernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
        this.usernameParameter = usernameParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
        this.passwordParameter = passwordParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getUsernameParameter() {
        return this.usernameParameter;
    }

    public final String getPasswordParameter() {
        return this.passwordParameter;
    }
}
~~~

### 过滤器如何进行加载
1. 使用SpringSecurity配置过滤器
    * DelegatingFilterProxy
~~~java
package org.springframework.web.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
public class DelegatingFilterProxy extends GenericFilterBean {

    @Nullable
    private String contextAttribute;

    @Nullable
    private WebApplicationContext webApplicationContext;

    @Nullable
    private String targetBeanName;

    private boolean targetFilterLifecycle = false;

    @Nullable
    private volatile Filter delegate;

    private final Object delegateMonitor = new Object();

    public DelegatingFilterProxy() {
    }
    
    public DelegatingFilterProxy(Filter delegate) {
        Assert.notNull(delegate, "Delegate Filter must not be null");
        this.delegate = delegate;
    }

    public DelegatingFilterProxy(String targetBeanName) {
        this(targetBeanName, null);
    }

    public DelegatingFilterProxy(String targetBeanName, @Nullable WebApplicationContext wac) {
        Assert.hasText(targetBeanName, "Target Filter bean name must not be null or empty");
        this.setTargetBeanName(targetBeanName);
        this.webApplicationContext = wac;
        if (wac != null) {
            this.setEnvironment(wac.getEnvironment());
        }
    }

    public void setContextAttribute(@Nullable String contextAttribute) {
        this.contextAttribute = contextAttribute;
    }

    @Nullable
    public String getContextAttribute() {
        return this.contextAttribute;
    }

    public void setTargetBeanName(@Nullable String targetBeanName) {
        this.targetBeanName = targetBeanName;
    }

   
    @Nullable
    protected String getTargetBeanName() {
        return this.targetBeanName;
    }
    
    public void setTargetFilterLifecycle(boolean targetFilterLifecycle) {
        this.targetFilterLifecycle = targetFilterLifecycle;
    }

    protected boolean isTargetFilterLifecycle() {
        return this.targetFilterLifecycle;
    }

    @Override
    protected void initFilterBean() throws ServletException {
        synchronized (this.delegateMonitor) {
            if (this.delegate == null) {
                // If no target bean name specified, use filter name.
                if (this.targetBeanName == null) {
                    this.targetBeanName = getFilterName();
                }
                // Fetch Spring root application context and initialize the delegate early,
                // if possible. If the root application context will be started after this
                // filter proxy, we'll have to resort to lazy initialization.
                WebApplicationContext wac = findWebApplicationContext();
                if (wac != null) {
                    this.delegate = initDelegate(wac);
                }
            }
        }
    }
    //过滤器方法
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Lazily initialize the delegate if necessary.
        Filter delegateToUse = this.delegate;
        if (delegateToUse == null) {
            synchronized (this.delegateMonitor) {
                delegateToUse = this.delegate;
                if (delegateToUse == null) {
                    WebApplicationContext wac = findWebApplicationContext();
                    if (wac == null) {
                        throw new IllegalStateException("No WebApplicationContext found: " +
                                "no ContextLoaderListener or DispatcherServlet registered?");
                    }
                    // 初始化过滤器
                    delegateToUse = initDelegate(wac);
                }
                this.delegate = delegateToUse;
            }
        }

        // Let the delegate perform the actual doFilter operation.
        invokeDelegate(delegateToUse, request, response, filterChain);
    }

    @Override
    public void destroy() {
        Filter delegateToUse = this.delegate;
        if (delegateToUse != null) {
            destroyDelegate(delegateToUse);
        }
    }

    @Nullable
    protected WebApplicationContext findWebApplicationContext() {
        if (this.webApplicationContext != null) {
            // The user has injected a context at construction time -> use it...
            if (this.webApplicationContext instanceof ConfigurableApplicationContext) {
                ConfigurableApplicationContext cac = (ConfigurableApplicationContext) this.webApplicationContext;
                if (!cac.isActive()) {
                    // The context has not yet been refreshed -> do so before returning it...
                    cac.refresh();
                }
            }
            return this.webApplicationContext;
        }
        String attrName = getContextAttribute();
        if (attrName != null) {
            return WebApplicationContextUtils.getWebApplicationContext(getServletContext(), attrName);
        }
        else {
            return WebApplicationContextUtils.findWebApplicationContext(getServletContext());
        }
    }

    //初始化过滤器
    protected Filter initDelegate(WebApplicationContext wac) throws ServletException {
        String targetBeanName = getTargetBeanName(); // springSecurityFilterChain
        Assert.state(targetBeanName != null, "No target bean name set");
        // 从spring容器中获取过滤器 FilterChainProxy
        Filter delegate = wac.getBean(targetBeanName, Filter.class);
        if (isTargetFilterLifecycle()) {
            delegate.init(getFilterConfig());
        }
        return delegate;
    }

    /**
     * Actually invoke the delegate Filter with the given request and response.
     * @param delegate the delegate Filter
     * @param request the current HTTP request
     * @param response the current HTTP response
     * @param filterChain the current FilterChain
     * @throws ServletException if thrown by the Filter
     * @throws IOException if thrown by the Filter
     */
    protected void invokeDelegate(
            Filter delegate, ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        delegate.doFilter(request, response, filterChain);
    }

    /**
     * Destroy the Filter delegate.
     * Default implementation simply calls {@code Filter.destroy} on it.
     * @param delegate the Filter delegate (never {@code null})
     * @see #isTargetFilterLifecycle()
     * @see javax.servlet.Filter#destroy()
     */
    protected void destroyDelegate(Filter delegate) {
        if (isTargetFilterLifecycle()) {
            delegate.destroy();
        }
    }

}

~~~