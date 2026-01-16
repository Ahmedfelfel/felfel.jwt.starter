# 🚀 Felfel JWT Starter

**Felfel JWT Starter** is a professional, high-performance, and stateless authentication library for **Spring Boot 3.x**. It simplifies JWT integration by handling token lifecycle management and security context population with zero boilerplate code.



---

## 💡 Why Felfel JWT?

Traditional JWT implementations often require a database hit (`UserDetailsService`) on every request to load user roles. **Felfel JWT Starter** eliminates this overhead:
- **Stateless Authorization**: User roles are embedded directly into the token.
- **Improved Latency**: The filter authorizes requests by parsing the token, skipping the database entirely for authenticated requests.
- **Developer Experience**: Auto-configures all necessary components as soon as the dependency is added.

---

## ✨ Features
- ✅ **Fully Stateless**: No session storage or repetitive DB queries.
- ✅ **Dynamic Expiration**: Supports durations like `15m`, `2h`, `7d`, etc.
- ✅ **Role-Based Security**: Automatically maps JWT claims to Spring Security `GrantedAuthorities`.
- ✅ **Cross-Language Support**: Works seamlessly with **Java**, **Groovy**, and **Kotlin**.

---

## 📦 Installation

Add the dependency to your project (via JitPack or your local repository):

### Maven
```xml
<dependency>
    <groupId>com.felfel</groupId>
    <artifactId>felfel-jwt-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```
### Gradle
```groovy
implementation 'com.felfel:felfel-jwt-starter:1.0.0'
```
---
## ⚙️ Configuration
Set your secret key in application.properties or as an Environment Variable.Important: The secret key must be at least 32 characters long.
# Properties 
```application.properties
felfel.jwt.secret=your_32_characters_long_secure_secret_key
```
# Environment Variable
```bash
export FELFEL_JWT_SECRET=your_32_characters_long_secure_secret_key
```
---

### 1. 📖 Usage Guide
Token Generation (Login)Inject JwtService into your AuthController. Use it to create both Access and Refresh tokens.Java@RestController
#### AuthController.java
```java
package com.felfel.jwtstarter.controller;
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // 1. Verify user credentials
        // 2. Load your UserPrincipal (must implement UserDetails)
        UserDetails user = userDetailsService.loadUserByUsername(loginRequest.getUsername());

        // 3. Create tokens using dynamic duration strings
        String accessToken = jwtService.createToken(user, "15m");
        String refreshToken = jwtService.createToken(user, "7d");

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
    }
}
```
---
### 2. Protecting API EndpointsInject JwtFilter into your Security Configuration
#### class.Java@Configuration
   ```Java
   @EnableWebSecurity
   public class SecurityConfig {

   @Autowired
   private JwtFilter felfelJwtFilter;

   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
   http
   .csrf(csrf -> csrf.disable())
   .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
   .authorizeHttpRequests(auth -> auth
   .requestMatchers("/auth/**").permitAll()
   .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
   .anyRequest().authenticated()
   )
   // Add Felfel JWT Filter before Spring's internal authentication filter
   .addFilterBefore(felfelJwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
   }
   }
```
---

## 🔍 Technical Specification

### 🛡️ Token Anatomy
The generated JWT is structured to carry all necessary identity information, ensuring a truly stateless experience.



| Claim   | Description                                                                                                             |
|:--------|:------------------------------------------------------------------------------------------------------------------------|
| `sub`   | **Subject**: Stores the unique username of the authenticated user.                                                      |
| `roles` | **Custom Claim**: An array of strings representing the user's `GrantedAuthority` (e.g., `["ROLE_ADMIN", "ROLE_USER"]`). |
| `iat`   | **Issued At**: Timestamp indicating when the token was generated.                                                       |
| `exp`   | **Expiration**: Timestamp indicating when the token becomes invalid.                                                    |

---

### 🔄 Data Flow (Inputs & Outputs)
This table summarizes how the core components of the library interact with your data.

| Component             | Input                                                      | Output / Effect                                                                                    |
|:----------------------|:-----------------------------------------------------------|:---------------------------------------------------------------------------------------------------|
| **`createToken`**     | `UserDetails` (Principal), `String` (Duration, e.g., "1h") | A signed, Base64-encoded **JWT String**.                                                           |
| **`extractUsername`** | Valid **JWT String**.                                      | The **Username** (Subject) extracted from the payload.                                             |
| **`extractRoles`**    | Valid **JWT String**.                                      | A `List<String>` of authorities stored in the token.                                               |
| **`isTokenValid`**    | **JWT String**, **Username**.                              | **Boolean**: `true` if signature is valid and token is not expired.                                |
| **`JwtFilter`**       | HTTP Header: `Authorization: Bearer <token>`               | Populates **`SecurityContextHolder`** with an authenticated `UsernamePasswordAuthenticationToken`. |

---

### ⚙️ Filter Logic Flow
1. **Intercept**: Filter catches the incoming HTTP request.
2. **Extract**: Reads the `Authorization` header.
3. **Parse**: `JwtService` decodes the token and verifies the signature.
4. **Authorize**: Authorities are extracted from the `roles` claim and injected into Spring Security's context.
5. **Proceed**: Request continues to the Controller without hitting the database.
---

## 🤝 Contributing
### Contributions are welcome! Please feel free to submit a Pull Request.

---
## 📄 License
This project is licensed under the MIT License.

---
© 2026 Felfel. All rights reserved.