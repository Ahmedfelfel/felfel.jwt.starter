package com.felfel.auth.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

/**
 * Service responsible for JWT lifecycle management: Creation, Extraction, and Validation.
 * Updated for JJWT 0.12.x API.
 */
public class JwtService {
    private final String secret;

    public JwtService(String secret) {
        this.secret = secret;
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    /**
     * Creates a signed JWT token containing user identity and authorities.
     */
    public String createToken(UserDetails user, String duration) {
        long millis;
        String input = duration.toLowerCase().trim();

        // extract duration from string
        long amount = Long.parseLong(input.replaceAll("[^0-9]", ""));

        if (input.endsWith("m")) {
            millis = amount * 60 * 1000;
        } else if (input.endsWith("h")) {
            millis = amount * 60 * 60 * 1000;
        } else if (input.endsWith("d")) {
            millis = amount * 24 * 60 * 60 * 1000;
        } else {
            // الافتراضي ثواني
            millis = amount * 1000;
        }
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        return Jwts.builder()
                .subject(user.getUsername())      // بدلاً من setSubject
                .claim("roles", roles)
                .issuedAt(new Date())             // بدلاً من setIssuedAt
                .expiration(new Date(System.currentTimeMillis() + millis)) // بدلاً من setExpiration
                .signWith(getSigningKey())        // يتم تحديد الخوارزمية تلقائياً من المفتاح
                .compact();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractAllClaims(token).get("roles", List.class);
    }

    public boolean isTokenValid(String token, String username) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.getSubject().equals(username) && !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    private Claims extractAllClaims(String token) {
        // في الإصدار الجديد نستخدم parser() بدلاً من parserBuilder()
        return Jwts.parser()
                .verifyWith(getSigningKey()) // بدلاً من setSigningKey
                .build()
                .parseSignedClaims(token)    // بدلاً من parseClaimsJaws
                .getPayload();               // بدلاً من getBody
    }
}