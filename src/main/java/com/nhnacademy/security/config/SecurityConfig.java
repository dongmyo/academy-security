package com.nhnacademy.security.config;

import com.nhnacademy.security.auth.LoginSuccessHandler;
import com.nhnacademy.security.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests()
                .requestMatchers("/teacher/**").hasAuthority("ROLE_TEACHER")
                .requestMatchers("/student/**").hasAuthority("ROLE_STUDENT")
                .requestMatchers("/redirect-index").authenticated()
                /* TODO #8: 실습 - 뭔가 이상하지 않나요? */
                .anyRequest().permitAll()
                .and()
            .formLogin()
                /* TODO #4: 실습 - 로그인 페이지 커스터마이징 */
                // ...
                .loginPage("/login")
                .loginProcessingUrl("/login-process")
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler(loginSuccessHandler())
                .and()
            .logout()
                /* TODO #6: 실습 - 로그아웃 페이지 커스터마이징 */
                // ...
                .deleteCookies("LOGIN")
                .invalidateHttpSession(true)
                .and()
            .csrf()
                .disable()
            .exceptionHandling()
                .accessDeniedPage("/error/403")
                .and()
            .build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(CustomUserDetailsService customUserDetailsService,
                                                         PasswordEncoder passwordEncoder) {
        // TODO #7: 실습 - UserDetailsService 와 PasswordEncoder 를 이용한 인증 처리 구현.
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customUserDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        return authenticationProvider;
    }

    @SuppressWarnings("deprecation")
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler();
    }

}
