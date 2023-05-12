package com.nhnacademy.security.config;

import com.nhnacademy.security.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity(debug = true)
@EnableMethodSecurity(prePostEnabled = true)
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
            // TODO : #4 oauth2Login()
            .oauth2Login()
                .clientRegistrationRepository(clientRegistrationRepository())
                .authorizedClientService(authorizedClientService())
                .and()
/*
            .formLogin()
                .usernameParameter("id")
                .passwordParameter("pwd")
                .loginPage("/auth/login")
                .loginProcessingUrl("/login")
                .and()
 */
            .logout()
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


    // TODO : #2 ClientRegistrationRepository with ClientRegistration.
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("naver")
            .clientId("i1uKug9bdiBnP3FLed03")
            .clientSecret("4RkRczMtEY")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .scope("name", "email", "profile_image")
            .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
            .authorizationUri("https://nid.naver.com/oauth2.0/authorize")
            .tokenUri("https://nid.naver.com/oauth2.0/token")
            .userInfoUri("https://openapi.naver.com/v1/nid/me")
            .userNameAttributeName("response")
            .build());
    }

    // TODO : #3 OAuth2AuthorizedClientService
    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

}
