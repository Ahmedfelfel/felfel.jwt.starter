package com.felfel.auth.config;

import com.felfel.auth.filter.JwtFilter;
import com.felfel.auth.service.JwtService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Autoconfiguration class to bootstrap the JWT library within the consumer application.
 */
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

    @Bean
    @ConditionalOnMissingBean
    public JwtFilter jwtFilter(JwtService service) {
        return new JwtFilter(service);
    }
}