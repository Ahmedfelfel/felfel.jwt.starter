package com.felfel.auth.config;

import com.felfel.auth.filter.JwtFilter;
import com.felfel.auth.filter.ReactiveJwtFilter;
import com.felfel.auth.service.JwtService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(JwtProperties props) {
        String secret = props.getSecret() != null ? props.getSecret() : System.getenv("FELFEL_JWT_SECRET");
        if (secret == null || secret.length() < 32) {
            throw new RuntimeException("JWT Secret is required and must be at least 32 characters long.");
        }
        return new JwtService(secret);
    }

    // LOAD ONLY IF SERVLET APP (e.g., User Service)
    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnMissingBean
    public JwtFilter jwtFilter(JwtService service) {
        return new JwtFilter(service);
    }

    // LOAD ONLY IF REACTIVE APP (e.g., API Gateway)
    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    @ConditionalOnMissingBean
    public ReactiveJwtFilter reactiveJwtFilter(JwtService service) {
        return new ReactiveJwtFilter(service);
    }
}