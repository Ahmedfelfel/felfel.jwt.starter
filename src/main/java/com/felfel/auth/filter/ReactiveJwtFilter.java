package com.felfel.auth.filter;

import com.felfel.auth.service.JwtService;
import jakarta.annotation.Nonnull;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Reactive Filter for WebFlux applications (like API Gateway).
 */
public class ReactiveJwtFilter implements WebFilter {

    private final JwtService jwtService;

    public ReactiveJwtFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, @Nonnull WebFilterChain chain) {
        String header =  exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                String username = jwtService.extractUsername(token);
                if (username != null && jwtService.isTokenValid(token, username)) {
                    List<String> roles = jwtService.extractRoles(token);
                    
                    // Convert List<String> to List<SimpleGrantedAuthority>
                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();

                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

                    // Reactive Security Context
                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                }
            } catch (Exception e) {
                // Token invalid or expired, continue without auth (Security Config will handle 401)
            }
        }
        return chain.filter(exchange);
    }
}