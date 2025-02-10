# Spring Boot 3 & JWT Authentication: Leveraging Spring Security’s Built-in Support

Author: **Nedim Hairlahović**

Hashtags: **#SpringBoot #JWT #SpringSecurity** 

## Overview

When implementing JWT authentication in Spring Boot, the default approach for most developers is to use a third-party library like jjwt, jose-jwt etc.
It’s simple, well-documented, and widely adopted, with countless tutorials and articles showcasing this method. But I couldn’t help but ask—what if we could achieve the same functionality using only Spring Security’s built-in support? Given that Spring Security is a robust and feature-rich framework, it should provide everything needed for JWT authentication, right?

After diving deep into the framework’s documentation and gaining valuable insights from the Spring community, particularly those shared by [Dan Vega](https://www.danvega.dev/), a Spring Developer Advocate at Broadcom, I put together a solution that eliminates external dependencies while keeping the implementation clean, maintainable and robust.

To ensure this approach is practical for real-world applications, we’ll integrate PostgreSQL for user data storage, Spring Data JPA for persistence, and Flyway for database migrations. This setup provides a solid foundation for building secure and scalable applications with modern authentication.

## Understanding JWT in Modern Authentication

We frequently come across terms like JWT (JSON Web Token) and OAuth2 when dealing with authentication and authorization. These concepts have become essential in modern software development, playing a crucial role in securing web applications, APIs, and microservices.

JWT is a compact, URL-safe token format used to securely transmit information between parties. It consists of three parts:

1. Header – Contains metadata about the token, including the algorithm used for signing.
2. Payload – Holds the claims (i.e., user information, roles, expiration time, etc.).
3. Signature – Ensures the token’s integrity and authenticity by verifying that its contents haven’t been altered or forged.

A key advantage of JWT over traditional session-based authentication is its **stateless** nature. Unlike session-based authentication, where user sessions are stored on the server, JWTs are self-contained and can be validated without server-side storage. This makes them particularly well-suited for scalable, distributed systems, where maintaining session state across multiple servers would be inefficient.

JWT is commonly used within OAuth2 and OpenID Connect for authentication and authorization. However, it can also be used independently, as we’ll see in this article, leveraging Spring Security’s built-in support to implement a clean and maintainable JWT authentication system.

To ensure security, JWTs must be signed to prevent unauthorized modifications. Signing a token guarantees that its contents haven't been changed and can be trusted by the recipient. We will explore both symmetric and asymmetric encryption for signing JWTs, symmetric using a shared secret key (HMAC) and asymmetric using a public-private key pair (RSA). Each approach has its use cases, and we’ll provide practical examples to demonstrate their implementation.

## What We’ll Be Building

The application will expose two simple endpoints:

1. An authentication endpoint where users can request a JWT token by providing their credentials.

   **[POST] /api/auth/token** 

2. A secured endpoint that requires a valid JWT token for access.

   **[GET] /api/secured**


The user will first authenticate by sending their credentials, receiving a signed JWT token in response. This token can then be included in subsequent requests to access protected resources. If the token is valid, access is granted; otherwise, the request is denied.

## Project Setup

Before we begin, ensure you have the following installed and set up:
- **Java 21 or higher** (Ensure it's installed and properly configured)
- **Maven 3.8 or higher** (For managing dependencies and building the project)
- **PostgreSQL running** (Either locally or via Docker)

  To run PostgreSQL using Docker, execute:
  ```sh
  docker run --name postgres-jwt -e POSTGRES_USER=admin -e POSTGRES_PASSWORD=admin -e POSTGRES_DB=jwt_demo -p 5432:5432 -d postgres:latest
  ```
- **HTTP client** (For testing API endpoints, e.g., Postman or curl)


The project requires the following dependencies:
- **Spring Web** – Enables building RESTful APIs with Spring MVC.
- **Spring Data JPA** – Provides an abstraction over JPA (Hibernate) for database interaction.
- **OAuth2 Resource Server** – Used for JWT authentication, leveraging Spring Security's built-in support.
- **Flyway Migration** – Manages database migrations to keep schemas versioned and consistent.
- **PostgreSQL Driver** – A JDBC driver required to connect to a PostgreSQL database.
- **Lombok** – Reduces boilerplate code (e.g., getters, setters, constructors) for better readability and less code, though optional.

Go to [Spring Initializr](https://start.spring.io/), add the mentioned dependencies and generate a new Spring Boot 3 project. In the next image, you can see how to configure everything properly.

<img width="1534" alt="Screenshot 2025-02-05 at 11 27 38" src="https://github.com/user-attachments/assets/1a3a1384-030c-4b4f-8598-06378a5a37ca" />
<p align="center"><i>Generate a Spring Boot project with the dependencies</i></p>

## Database Configuration Setup

Since we included Spring Data JPA, you need to configure the database connection. Add the following properties to your `application.properties` or `application.yml` file:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/jwt-auth-demo
spring.datasource.username=postgres
spring.datasource.password=postgres
spring.jpa.hibernate.ddl-auto=none
```

The database URL specifies `localhost:5432/jwt-auth-demo` as the connection string. The `jwt-auth-demo` is the name of the database and can be changed as needed to match your desired database name. The setting `spring.jpa.hibernate.ddl-auto` is configured to `none` because we are using Flyway for database migrations rather than relying on Hibernate to automatically create or update the schema. Flyway will handle database creation and schema management instead.

Now that the database is configured, let's create a simple test controller to verify that the application is up and running.
```java
@RestController
public class TestController {

    @RequestMapping("/api/secured")
    public String secured() {
        return "This is a secured endpoint";
    }
}
```
The `/api/secured` endpoint will return a simple message to confirm that the application is responsive. If you try to access this endpoint, you will be prompted to enter a username and password, as it is secured. However, authentication is not yet fully configured, so it won't work at this stage. This is expected, as we haven't set up the authentication provider and security configurations yet. We'll handle this in the next steps.

## Setting User Storage

To authenticate users, we need a User entity that will represent the user data stored in the database. We’ve created the following `User.java` class in the `model` package:
```java
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String password;

    private String firstName;

    private String lastName;
}
```

 The `@Entity` annotation marks it as a JPA entity that will be mapped to a table in the database. Since we’re using Flyway for database migrations, we’ll create the following Flyway migration file in the `resources/db/migration` folder (Flyway’s default migration path):
 
 **Migration 1 - Create Users Table**:
```sql
create table users
(
    id          serial primary key,
    username    varchar(255) not null unique,
    password    varchar(255) not null,
    first_name  varchar(255) not null,
    last_name   varchar(255) not null
);
```
This SQL script creates the users table with columns for the user's ID, username, password, and full name.

Next, we insert a sample user with the username user and password user (hashed with BCrypt for security) to facilitate testing:

**Migration 2 - Insert Sample User:**
```sql
insert into users (username, password, first_name, last_name)
values ('user', '$2a$10$XrA1Dirt.xM9Tn91FV.3HOLahRDHvVjaowYsSCj.HC5Q/rIBwqfjy', 'user', 'user');
```

The password here is stored as a BCrypt hash. By storing passwords as hashes (and not in plain text), we are adhering to good security practices. However, keep in mind that placing static user data in migration scripts, especially passwords, creates security risks. If an attacker gains access to the migration files, they could easily retrieve and compromise your user credentials. It's best to use secure, dynamic methods for handling user creation and authentication (e.g., using an admin interface or external user management service).

Run the application, and you’ll see that the `users` table is created and populated with sample user data for testing purposes. You can verify this by using pgAdmin or any other PostgreSQL client.

## Spring Security Configuration

To start implementing authentication, we’ll create a central security configuration class. This class is responsible for configuring the security settings for the application, including authorization, authentication, and JWT-based security for our endpoints.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/api/auth/token").permitAll();
                    auth.anyRequest().authenticated();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> {
                    oauth2.jwt(withDefaults());
                })
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public AuthenticationManager authManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(authProvider);
    }
}
```

`SecurityFilterChain` bean configures HTTP security for our application. It disables CSRF protection (which is not needed for stateless authentication, but for session-based authentication should be enabled), allows public access to the `/api/auth/token` endpoint (used for obtaining the JWT token), and requires authentication for all other endpoints. It also sets the session management to stateless since we are using JWT for authentication instead of sessions. The `oauth2ResourceServer` part configures the application to authenticate using JWT tokens, making use of Spring Security’s built-in support for OAuth2 resource servers.

The `BCryptPasswordEncoder` bean is used for encoding passwords. This is important for securely storing user credentials in the database. BCrypt is a strong hashing algorithm that is resistant to brute-force attacks.

The `AuthenticationManager` bean is used for handling authentication. It’s configured with a `DaoAuthenticationProvider`, which connects the application to the user store (in our case, the database) through the `UserDetailsService` and verifies the user’s credentials using the PasswordEncoder.

This class lays the foundation for integrating user authentication with JWT and Spring Security.


## Customizing User Authentication with UserDetailsService

The `UserDetailsService` is a core interface in Spring Security used for loading user-specific data. It defines a method `loadUserByUsername()` that Spring Security uses to retrieve user information (such as username, password, and roles) from the underlying data store during authentication.

We created a custom implementation of this service with the following `AuthUserDetailsService` class:
```java
@Service
@RequiredArgsConstructor
public class AuthUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(AuthUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}
```

The repository method `findByUsername`, which searches the users table for a user with the given username, is defined as a Spring JPA interface method:
```java
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
```

The `AuthUser` class implements the `UserDetails` interface, which provides all the necessary methods that Spring Security requires for user authentication and authorization, and checking account status (e.g., if the account is locked or expired). Here’s the `AuthUser` class:
```java
@RequiredArgsConstructor
public class AuthUser implements UserDetails {

    private final User user;

    @Override
    public String getUsername() { return user.getUsername(); }

    @Override
    public String getPassword() { return user.getPassword(); }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Return a list of roles or authorities assigned to the user.
        return List.of();
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
```

## JWT Configuration

Since we are integrating Spring Security as an OAuth2 Resource Server with JWT (JSON Web Token) authentication, we need to configure both a JWT encoder and decoder to handle the signing and verification of tokens.
```java
@Configuration
public class JwtConfig {

    @Value("${jwt.key}")
    private String jwtKey;

    @Bean
    public JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableSecret<>(jwtKey.getBytes()));
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] bytes = jwtKey.getBytes();
        SecretKeySpec originalKey = new SecretKeySpec(bytes, 0, bytes.length,"RSA");
        return NimbusJwtDecoder.withSecretKey(originalKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }
}
```

The `jwtEncoder` bean uses the NimbusJwtEncoder to create JWT tokens. It requires a signing key, which is provided as a byte array. In our case, we’re using a **symmetric** encryption method, meaning the same key is used for both signing the JWT (encoding) and verifying it (decoding). The `jwtDecoder` bean is responsible for decoding the incoming JWTs. It uses the same `jwtKey` for verification. In this example, we’re using the HS256 algorithm, which is a symmetric encryption algorithm where the same key is used for both signing and verification.

The `jwt.key` used in the configuration is the secret key used for both signing and verifying the JWT. It is defined in the application properties as follows:
```properties
jwt.key=YzEyMzR0bXZxQzRmNTZ2cEFoUGVpMWdIajU3aWdoZ2g
```

As mentioned earlier, the configuration uses symmetric encryption (HS256), i.e. the same key is used for both encoding and decoding. This simplifies key management but also means that the secret key must be protected from unauthorized access. For production environments, **do not hardcode** the JWT key in the `application properties` file. Instead, consider injecting the key from a secure external source, such as an environment variable or a secrets management system (e.g., AWS Secrets Manager, HashiCorp Vault, or CredHub). Hardcoding sensitive information directly into the codebase or configuration files is a security risk, as it exposes the key to potential leaks or unauthorized access.

## Implementing Login and Token Generation

The authentication process involves validating the user's credentials and generating a JWT token upon successful authentication. This is done by the `AuthService`, which coordinates authentication and token generation.
```java
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;

    public AuthResponse authenticate(AuthRequest authRequest) {
        var token = new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword());
        Authentication authentication = authenticationManager.authenticate(token);

        String jwtToken = jwtTokenService.generateToken(authentication);
        Long expiresAt = jwtTokenService.extractExpirationTime(jwtToken);

        return new AuthResponse(jwtToken, authentication.getName(), expiresAt);
    }
}
```

This service ties together the authentication flow and JWT token generation to allow users to log in and receive an access token for subsequent API requests. The `JwtTokenService` is responsible for generating JWT tokens and decoding them. It uses the `JwtEncoder` to generate tokens and the `JwtDecoder` to extract data from tokens (like the expiration time).
```java
@Service
@RequiredArgsConstructor
public class JwtTokenService {

    private final JwtEncoder encoder;
    private final JwtDecoder decoder;

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        String scope = "ROLE_ADMIN";
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();
        var encoderParameters = JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims);
        return this.encoder.encode(encoderParameters).getTokenValue();
    }

    public Long extractExpirationTime(String token) {
        Jwt jwt = decoder.decode(token);
        var exp = (Instant) jwt.getClaim("exp");
        return exp.toEpochMilli();
    }
}
```

The settings (claims and expiration time) can be adjusted here based on project-specific requirements.

To handle the authentication process, where users provide credentials and receive a JWT upon successful authentication, we add a controller:
```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/token")
    public AuthResponse login(@RequestBody AuthRequest authRequest) {
        return authService.authenticate(authRequest);
    }
}
```

## Running and Testing the Application

With all configurations in place, we can now run and test the application. Ensure your database is running, then start the Spring Boot application (via Maven, JAR file, or directly in an IDE like IntelliJ IDEA).

Run the application using Maven with the following command:
```sh
./mvnw spring-boot:run
```

Your application should start successfully without errors. The first step is to obtain an access JWT token via the authentication endpoint. 
We’ll use `curl` for this, but you can also use Postman or any other HTTP client.


Example request using `curl`:
```sh
curl -X POST http://localhost:8080/api/auth/token \
     -H "Content-Type: application/json" \
     -d '{"username": "user", "password": "user"}'
```

Response:
```json
{
  "token": "JWT_TOKEN",
  "username": "user",
  "expiresAt": 1700000000000
}
```

You can use the received JWT token to access secured endpoints by adding an Authorization header.

Example request using `curl`:
```sh
curl -X GET http://localhost:8080/api/secured \
     -H "Authorization: Bearer JWT_TOKEN"
```

Replace `JWT_TOKEN` with the actual token obtained from the authentication request, and you should get response:
```
This is an secured endpoint
```

## Asymmetric Key Signature in JWT Authentication

In the previous implementation, we used **symmetric encryption** for signing JWTs. Symmetric encryption (e.g., HMAC using HS256) uses a single shared key for both signing and verifying the token. This means the same key must be securely stored on both the authentication server (issuer) and the resource servers (verifiers). In our case, both are part of the same backend application, so the key remains within the same system, but this approach becomes less secure in distributed environments.

To enhance security, we can switch to **asymmetric encryption**, which uses a public/private key pair. Asymmetric encryption (e.g., RSA with RS256) uses a private key to sign the JWT and a public key to verify it.
The private key remains secure on the authentication server, while the public key can be freely shared with services that need to validate JWTs. This setup prevents services from modifying or forging tokens while allowing them to verify authenticity without direct access to the signing key.

To implement asymmetric encryption, we first generate an RSA key pair. On macOS and Linux, you can use `OpenSSL`. I believe there are similar tools available for Windows as well.
```sh
# Generates a new RSA private key with a length of 2048 bits and saves it in keypair.pem.
openssl genrsa -out keypair.pem 2048

# Extracts the public key from the private key and saves it in public.pem. 
openssl rsa -in keypair.pem -pubout -out public.pem

# Converts the private key into the PKCS#8 format, which is widely supported by libraries and frameworks.
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem
```

This will generate:
- `public.pem` → The public key, which is shared with resource servers to validate tokens.
- `private.pem` → The private key, which is kept secure on the authentication server to sign tokens.

We store the generated keys in our application’s properties file:
```properties
rsa.private-key=classpath:certs/private.pem
rsa.public-key=classpath:certs/public.pem
```

The key files are stored inside the application’s classpath (e.g., `src/main/resources/certs/`). In a production-ready environment, hardcoding keys in your application or storing them in the classpath is not secure. Instead, you should store them in a secure secrets management system (e.g., AWS Secrets Manager, HashiCorp Vault, or CredHub) or load them as environment variables (`RSA_PRIVATE_KEY` and `RSA_PUBLIC_KEY`) and inject them into the application at runtime.

We define a configuration class to map these properties to Java objects:
```java
@Data
@Configuration
@ConfigurationProperties(prefix = "rsa")
public class RsaKeyProperties {
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
}
```

This class automatically maps the RSA keys from the application properties to Java objects (`RSAPublicKey` and `RSAPrivateKey`), making them easily accessible in our JWT configuration.

We now update our JwtConfig class to use the RSA key pair for signing and verification:
```java
@Configuration
@RequiredArgsConstructor
public class JwtConfig {

    private final RsaKeyProperties rsaKeys;

    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeys.getPublicKey())
                .privateKey(rsaKeys.getPrivateKey())
                .build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeys.getPublicKey()).build();
    }
}
```

Signing (`JwtEncoder`) uses the private key to sign JWTs using the RS256 algorithm and stores the key pair in a JWKSet for easy access by the encoder.
Verification (`JwtDecoder`) uses the public key to verify JWTs, ensuring that only JWTs signed with the correct private key are accepted.

Additionally, update `JwtTokenService` to switch from HMAC (HS256) to RSA (RS256) for JWT signing, ensuring stronger security with asymmetric encryption:
```java
var encoderParameters = JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims);
```

## Conclusion

In this article, we explored how to implement JWT authentication in Spring Boot using only Spring Security’s built-in features. By eliminating external dependencies, we achieved a clean and maintainable solution.

We covered JWT fundamentals, its structure, and the importance of signing for security. Through symmetric and asymmetric encryption examples, we demonstrated how to securely generate and validate tokens. The complete code for both implementations can be found on [GitHub](https://github.com/evoila-bosnia/spring-jwt-auth).

Following best practices—such as short-lived tokens and proper validation—is crucial for a secure implementation. With this approach, you can confidently integrate JWT authentication into your Spring Boot applications.

