package xb.hou;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @title: AppRun
 * @Author xbhou
 * @Date: 2021-06-15 22:16
 * @Version 1.0
 */
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
