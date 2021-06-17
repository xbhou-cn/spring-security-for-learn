package xb.hou.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
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
//@Configuration
@RequiredArgsConstructor
public class SecurityConfig1 extends WebSecurityConfigurerAdapter {
    final private PasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("xbhou").password(passwordEncoder.encode("123456")).roles("admin");
    }
}
