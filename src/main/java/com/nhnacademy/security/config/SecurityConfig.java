package com.nhnacademy.security.config;

import com.nhnacademy.security.auth.CustomLogoutSuccessHandler;
import com.nhnacademy.security.auth.LoginSuccessHandler;
import com.nhnacademy.security.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests()
                .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/private-project/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MEMBER")
                .requestMatchers("/project/**").authenticated()
                .requestMatchers("/redirect-index").authenticated()
                .anyRequest().permitAll()
                .and()
            .requiresChannel()
                .requestMatchers("/admin/**").requiresSecure()
                .requestMatchers("/private-project/**").requiresSecure()
                .requestMatchers("/project/**").requiresSecure()
                .anyRequest().requiresInsecure()
                .and()
            .formLogin()
                .usernameParameter("id")
                .passwordParameter("pwd")
                .loginPage("/auth/login")
                .loginProcessingUrl("/login")
                // TODO #4: login success handler 설정
                .successHandler(loginSuccessHandler(null))
                .and()
            .logout()
                .deleteCookies("SESSION")
                .invalidateHttpSession(true)
                // TODO #7: logout success handler 설정
                .logoutSuccessHandler(logoutSuccessHandler(null))
                .and()
            .csrf()
                .and()
            .sessionManagement()
                .sessionFixation()
                    .none()
                .and()
            .headers()
                .defaultsDisabled()
                .frameOptions().sameOrigin()
                .and()
            .exceptionHandling()
                .accessDeniedPage("/error/403")
                .and()
            .build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(CustomUserDetailsService customUserDetailsService) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customUserDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());

        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // TODO #3: login success handler bean
    @Bean
    public AuthenticationSuccessHandler loginSuccessHandler(RedisTemplate<String, Object> redisTemplate) {
        return new LoginSuccessHandler(redisTemplate);
    }

    // TODO #6: logout success handler bean
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(RedisTemplate<String, Object> redisTemplate) {
        return new CustomLogoutSuccessHandler(redisTemplate);
    }

}
