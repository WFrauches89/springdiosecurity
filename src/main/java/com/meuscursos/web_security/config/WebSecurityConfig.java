package com.meuscursos.web_security.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import static org.springframework.security.config.Customizer.withDefaults;



@Configuration

public class WebSecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);
    @Bean
    public BCryptPasswordEncoder encoder() {
        logger.info("Iniciando BCrypt...");
        return new BCryptPasswordEncoder();
    }

    private static final String[] SWAGGER_WHITELIST = {
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**"
    };
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        logger.info("Iniciando Security Filter Chain...");
        http
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))

                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration configuration = new CorsConfiguration();
                    configuration.addAllowedOrigin("*");
                    configuration.addAllowedMethod("*");
                    configuration.addAllowedHeader("*");
                    return configuration;
                })).csrf(csrf -> csrf.disable()) // desativa a proteção CSRF
                .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(SWAGGER_WHITELIST).permitAll()
                        .requestMatchers("/").permitAll()
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                        .requestMatchers(HttpMethod.POST,"/users").permitAll()
                        .requestMatchers(HttpMethod.GET,"/users").hasAnyRole("USERS", "MANAGERS")
                        .requestMatchers("/managers").hasRole("MANAGERS")
                        .anyRequest().authenticated()

                )    .sessionManagement(sessionManagement -> {
                    try {
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                        logger.info("Session management configuration: {}", SessionCreationPolicy.STATELESS);
                    } catch (Exception e) {
                        logger.error("Erro ao configurar session management", e);
                    }
                })
                .httpBasic(withDefaults());
        logger.info("Build "+http);
        return http.build();
    }
}