package com.nhnacademy.security.config;

import com.nhnacademy.security.filter.UsernameAdjustingFilter;
import javax.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
            .formLogin()
                .and()
            .logout()
                .and()
            .csrf()
                .disable()
            .sessionManagement()
                .sessionFixation()
                    .none()
                .and()
            // TODO #3: UsernameAdjustingFilter를 UsernamePasswordAuthenticationFilter 앞에 추가
            .addFilterBefore(usernameAdjustingFilter(), UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    // TODO #1: username을 email 형태로 변경
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails admin = User.withUsername("admin@nhnacademy.com")
                .password("{noop}admin")
                .authorities("ROLE_ADMIN")
                .build();

        UserDetails member = User.withUsername("member@nhnacademy.com")
                .password("{noop}member")
                .authorities("ROLE_MEMBER")
                .build();

        UserDetails guest = User.withUsername("guest@nhnacademy.com")
            .password("{noop}guest")
            .authorities("ROLE_GUEST")
            .build();

        return new InMemoryUserDetailsManager(admin, member, guest);
    }

    // TODO #4: UsernameAdjustingFilter를 빈으로 등록
    @Bean
    public UsernameAdjustingFilter usernameAdjustingFilter() {
        return new UsernameAdjustingFilter("username");
    }

}
