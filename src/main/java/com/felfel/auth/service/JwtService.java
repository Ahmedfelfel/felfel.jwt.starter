package com.felfel.auth.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.security.Key;
import java.time.Duration;
import java.util.Date;
import java.util.List;

/**
 * Service responsible for JWT lifecycle management: Creation, Extraction, and Validation.
 */
public class JwtService {
    private final String secret;

    public JwtService(String secret) { this.secret = secret; }

    private Key getSigningKey() { return Keys.hmacShaKeyFor(secret.getBytes()); }

    /**
     * Creates a signed JWT token containing user identity and authorities.
     * @param user The UserDetails principal.
     * @param duration Duration string (e.g., "15m", "24h", "7d").
     * @return A signed JWT string.
     */
    public String createToken(UserDetails user, String duration) {
        long millis = Duration.parse("PT" + duration.toUpperCase()).toMillis();
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();

        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("roles", roles) // Embed roles for stateless authorization
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + millis))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                .parseClaimsJws(token).getBody().get("roles", List.class);
    }

    /**
     * Validates if the token is well-formed, not expired, and matches the username.
     */
    public boolean isTokenValid(String token, String username) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                    .parseClaimsJws(token).getBody();
            return claims.getSubject().equals(username) && !claims.getExpiration().before(new Date());
        } catch (Exception e) { return false; }
    }
}