package com.nhnacademy.security.config;

import com.nhnacademy.security.filter.UsernameAdjustingFilter;
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
                // TODO #2: 실습 - 최대 세션 갯수를 1개로 제한하시오
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true)
                .and()
                .sessionFixation()
                    .none()
                .and()
            // TODO #4: 실습 - UsernameAdjustingFilter를 UsernamePasswordAuthenticationFilter 앞에 추가하시오.
            .addFilterBefore(usernameAdjustingFilter(), UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    // TODO #3: email 형태였던 username을 다시 원래대로 돌림
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin")
                .authorities("ROLE_ADMIN")
                .build();

        UserDetails member = User.withUsername("member")
                .password("{noop}member")
                .authorities("ROLE_MEMBER")
                .build();

        UserDetails guest = User.withUsername("guest")
            .password("{noop}guest")
            .authorities("ROLE_GUEST")
            .build();

        return new InMemoryUserDetailsManager(admin, member, guest);
    }

    @Bean
    public UsernameAdjustingFilter usernameAdjustingFilter() {
        return new UsernameAdjustingFilter("username");
    }

}
