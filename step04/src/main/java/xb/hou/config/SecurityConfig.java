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

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //配置退出
        http.logout().logoutUrl("/logout").logoutSuccessUrl("/user/logout").permitAll();
        http.exceptionHandling().accessDeniedPage("/unauth.html");
        http.formLogin().loginPage("/login.html").loginProcessingUrl("/user/login").defaultSuccessUrl("/success.html").permitAll()
                .and().authorizeRequests().anyRequest().authenticated()
                .and().rememberMe().tokenRepository(repository)
                .tokenValiditySeconds(3600) // 过期时间，单位为秒
                .and().csrf().disable();
    }
}
