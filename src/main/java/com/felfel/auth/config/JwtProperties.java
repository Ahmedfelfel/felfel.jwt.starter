package com.felfel.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * This class maps configuration properties with the prefix "felfel.jwt".
 * It allows users to override settings via application.properties or ENV variables.
 */
@ConfigurationProperties(prefix = "felfel.jwt")
public class JwtProperties {

    /**
     * The secret key used for signing JWTs.
     * Mapping: FELFEL_JWT_SECRET (Environment Variable)
     */
    private String secret;

    // Getter and Setter (Required for Spring to inject the values)
    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
}