# Spring Security 6 & JWT Authentication Architecture

A production-grade reference implementation of JSON Web Token (JWT) authentication, token rotation, and blacklisting built with Spring Boot 3, Spring Security 6, and Java 21.

---

## Architectural Focus and Scope Notice

> **Important Scope Note:**  
> Input validations (`@Valid`, Bean Validation constraints) and complex database constraints (foreign key cascades, auditing tables, domain models) were **intentionally omitted** from this project.  
> The sole objective of this codebase is to provide a clean, uncompromising, and deep demonstration of **JWT security mechanics, cryptographic key handling, token lifecycle orchestration, rotation, and revocation**.

---

## Key Security Innovations Often Overlooked in Industry Tutorials

Most online guides and tutorials implement JWT in a trivialized manner that introduces severe security vulnerabilities into production systems. This project explicitly addresses those critical gaps:

### 1. Hashed Refresh Tokens in Database (One-Way SHA-256 Storage)
* **The Industry Flaw:** Almost all tutorials store raw UUID refresh tokens directly in the database as plaintext strings. If the database is breached (via SQL injection, unauthorized dump, or backup leak), attackers can impersonate every active user for days or weeks.
* **Our Implementation:** Only one-way SHA-256 hashes of refresh tokens are persisted in the database. The client receives the raw UUID (`rawToken`), while the database stores `hashToken(rawToken)`. Even if the database is completely compromised, leaked hashes cannot be presented to the API to forge sessions because the hashing algorithm is one-way.

### 2. Refresh Token Rotation with Replay Attack & Theft Detection
* **The Industry Flaw:** Many implementations reuse the same refresh token indefinitely until it expires, allowing compromised tokens to be exploited repeatedly.
* **Our Implementation:** Every call to `/api/auth/refresh` implements **Token Rotation**: the old refresh token is immediately invalidated (`revoked = true`), and an entirely new refresh token is issued.
* **Automated Session Revocation:** If an already-revoked refresh token is ever submitted, the application detects a token theft / replay attack. The system immediately invokes `refreshTokenRepository.revokeAllByUser(user)`, invalidating **all active refresh tokens across every device** for that user.

### 3. In-Memory Blacklist for Stateless Access Token Revocation
* **The Industry Flaw:** Because JWTs are stateless and self-contained, standard logout endpoints merely delete client-side cookies or tell the frontend to discard the token. The token itself remains cryptographically valid until its expiration timestamp, leaving a window of vulnerability if intercepted.
* **Our Implementation:** `TokenBlackListService` implements a thread-safe `ConcurrentHashMap` blacklist. When a user logs out, the access token's remaining lifetime is computed from its `expiration` claim, and it is stored in the blacklist. Every incoming request verified by `JwtAuthenticationFilter` checks this blacklist and immediately rejects revoked tokens with `401 Unauthorized`.
* **RAM Optimization:** An automated `@Scheduled` background task runs every 15 minutes to purge expired tokens from the blacklist map. Because expired tokens naturally fail cryptographic validation anyway, keeping them in RAM is unnecessary.

### 4. HttpOnly, SameSite, and Path-Scoped Cookie Transport
* **The Industry Flaw:** Storing refresh tokens in browser `localStorage` or `sessionStorage` exposes them to Cross-Site Scripting (XSS) extraction.
* **Our Implementation:** Refresh tokens are encapsulated in a `ResponseCookie`:
  * `httpOnly(true)`: Inaccessible to client-side JavaScript (`document.cookie`), neutralizing XSS token theft.
  * `sameSite("Strict")`: Eliminates Cross-Site Request Forgery (CSRF).
  * `path("/api/auth")`: Restricts cookie transmission strictly to authentication endpoints, preventing the cookie from being unnecessarily sent on every API resource request.
  * `maxAge(0)`: On logout, the server instructs the browser to immediately expunge the cookie from storage.

### 5. Filter Bypass on Public Endpoints (`shouldNotFilter`)
* **The Industry Flaw:** In single-page applications (React, Angular, Vue) or mobile apps, HTTP interceptors (such as Axios interceptors) automatically append the `Authorization: Bearer <token>` header to all outgoing requests. When an access token expires, the client calls `/api/auth/refresh` to obtain a new pair. If a custom JWT filter attempts to validate the header on the refresh request, it throws `ExpiredJwtException` and rejects the call with 401 before `SecurityConfig`'s `permitAll()` can ever evaluate it, locking the user out.
* **Our Implementation:** `JwtAuthenticationFilter` overrides `shouldNotFilter()` to bypass public authentication endpoints (`/api/auth/register`, `/api/auth/login`, `/api/auth/refresh`, `/api/auth`). This prevents the expired access token from triggering a filter-level rejection during a refresh request.

---

## Architecture Overview

```
                      +-----------------------------------+
                      |         Incoming Request          |
                      +-----------------+-----------------+
                                        |
                   Does path match shouldNotFilter()?
                                        |
                     +------------------+------------------+
                     | YES                                 | NO
                     v                                     v
         +-----------------------+             +-----------------------+
         | Bypass Filter Chain   |             | JwtAuthFilter Check   |
         | (register/login/refr) |             +-----------+-----------+
         +-----------+-----------+                         |
                     |                        Is Token Blacklisted?
                     |                         (TokenBlackListService)
                     |                                     |
                     |                   +-----------------+-----------------+
                     |                   | YES                               | NO
                     |                   v                                   v
                     |        +---------------------+             +---------------------+
                     |        | 401 Unauthorized    |             | Validate Signature  |
                     |        | (token_revoked)     |             | & Populate Context  |
                     |        +---------------------+             +----------+----------+
                     |                                                       |
                     +--------------------------+----------------------------+
                                                |
                                                v
                               +---------------------------------+
                               |    SecurityFilterChain Rules    |
                               |  - /api/auth/** -> permitAll    |
                               |  - /api/auth/logout -> auth'd   |
                               |  - /api/private/**  -> auth'd   |
                               +---------------------------------+
```

---

## Technical Stack

* **Language:** Java 21
* **Framework:** Spring Boot 3.x (Spring Security 6, Spring Data JPA, Spring Web)
* **JWT Library:** `io.jsonwebtoken` (JJWT) `0.12.6`
* **Database:** PostgreSQL
* **Password Hashing:** BCrypt (`BCryptPasswordEncoder`)
* **Build Tool:** Maven Wrapper (`mvnw`)

---

## Project Structure

```
src/main/java/com/akt/security/jwt/
├── JwtApplication.java               # Application entry point with @EnableScheduling
├── config/
│   ├── SecurityConfig.java           # SecurityFilterChain, AuthenticationProvider, CORS, Exception Handlers
│   └── SecurityProperties.java       # Configuration properties bound to "jwt.*"
├── controller/
│   ├── AuthController.java           # Public auth endpoints & cookie management
│   └── PrivateController.java        # Protected resource endpoints (@PreAuthorize)
├── dto/
│   ├── AuthResponse.java             # Record returning accessToken and raw refreshToken
│   ├── CurrentUser.java              # Principal payload stored in SecurityContext
│   ├── LoginRequest.java             # Username & password request DTO
│   ├── RefreshTokenRequest.java      # Raw refresh token request DTO
│   └── RegisterRequest.java          # User registration DTO
├── exception/
│   ├── GlobalExceptionHandler.java   # Centralized REST exception handling
│   ├── TokenNotFoundException.java   # 401 when token cannot be located
│   ├── TokenNotValidException.java   # 401 when token is revoked, expired, or locked
│   └── UserAlreadyExistsException.java # 409 conflict during registration
├── model/
│   ├── CustomUserDetails.java        # Spring Security UserDetails adapter
│   ├── RefreshToken.java             # Entity with SHA-256 hashed token and @Transient rawToken
│   ├── Role.java                     # Role enumeration (USER, ADMIN)
│   └── User.java                     # JPA User entity
├── repository/
│   ├── RefreshTokenRepository.java   # Data access with custom revokeAllByUser queries
│   └── UserRepository.java           # Data access for User entities
└── security/
    ├── CustomUserDetailsService.java # UserDetailsService loading from UserRepository
    ├── JwtAuthenticationFilter.java  # OncePerRequestFilter with blacklist checks and shouldNotFilter
    ├── JwtService.java               # JWT creation, claims parsing, HMAC-SHA256 signing
    └── TokenBlackListService.java    # ConcurrentHashMap in-memory blacklist with TTL auto-cleanup
```

---

## Configuration

In `src/main/resources/application.properties`:

```properties
spring.application.name=jwt

spring.datasource.url=jdbc:postgresql://localhost:5432/jwt
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.username=postgres
spring.datasource.password=postgres

spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=true
spring.jpa.open-in-view=false

# 256-bit Base64-encoded secret signing key (defaults provided for seamless out-of-the-box local execution)
jwt.access-token=${JWT_ACCESS_TOKEN:/NKrzqkQTQMc4a0M5kuvSDkF8+VOrAcadpg0lrvQgFsAn1irbG4g1KB3O2kvA6pCpYVqs2L98DDza68XOCeVkg==}
jwt.access-token-expiration=15m
jwt.refresh-token-expiration=7d
jwt.issuer=jwt-security
jwt.audience=jwt-client
```

---

## Building and Running

### Prerequisites
* Java 21 installed (`java -version`)
* PostgreSQL running on port `5432` with a database named `jwt`

### Run using Maven Wrapper
```bash
# Clone the repository
git clone https://github.com/AKeremT/Spring-Security-JWT-.git
cd Spring-Security-JWT-

# Build and run
./mvnw spring-boot:run
```

---

## End-to-End Postman Testing Scenarios

Use the following step-by-step requests in Postman to test the complete lifecycle.

### Step 1: User Registration
* **Method:** `POST`
* **URL:** `http://localhost:8080/api/auth/register`
* **Headers:** `Content-Type: application/json`
* **Authorization:** `No Auth`
* **Body (raw JSON):**
```json
{
  "username": "johndoe",
  "password": "Password123!",
  "email": "johndoe@example.com"
}
```
* **Expected Response (`200 OK`):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsIn...",
  "refreshToken": "6b379e4d-2bb7-4e3b-9e46-17b545d65609"
}
```
* **Note:** Check the **Cookies** tab in Postman. A cookie named `refreshToken` with attributes `HttpOnly; SameSite=Strict; Path=/api/auth` is automatically stored.

---

### Step 2: User Authentication (Login)
* **Method:** `POST`
* **URL:** `http://localhost:8080/api/auth/login`
* **Headers:** `Content-Type: application/json`
* **Authorization:** `No Auth`
* **Body (raw JSON):**
```json
{
  "username": "johndoe",
  "password": "Password123!"
}
```
* **Expected Response (`200 OK`):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsIn...",
  "refreshToken": "4df11202-b258-450e-b2d9-1051515bbad5"
}
```
*(Copy the `accessToken` and `refreshToken` for subsequent steps).*

---

### Step 3: Access Protected Resource
* **Method:** `GET`
* **URL:** `http://localhost:8080/api/private/user`
* **Authorization:** Select `Bearer Token`, paste the `accessToken` from Step 2.
* **Body:** None
* **Expected Response (`200 OK`):**
```text
Hello User from PrivateController
```

---

### Step 4: Refresh Token Rotation
* **Method:** `POST`
* **URL:** `http://localhost:8080/api/auth/refresh`
* **Headers:** `Content-Type: application/json`
* **Authorization:** `No Auth`
* **Body (raw JSON):**
```json
{
  "token": "4df11202-b258-450e-b2d9-1051515bbad5"
}
```
*(Note: If Postman automatically sends cookies, you can omit the body entirely).*
* **Expected Response (`200 OK`):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "9e1c3902-69ec-4581-80ec-fc8a06950294"
}
```
* **Observation:** A brand new Access Token and a brand new Refresh Token are returned. The old refresh token (`4df11202...`) is now revoked in the database.

---

### Step 5: Logout (Session Termination & Blacklisting)
* **Method:** `POST`
* **URL:** `http://localhost:8080/api/auth/logout`
* **Authorization:** Select `Bearer Token`, paste the latest `accessToken` from Step 4.
* **Headers:** `Content-Type: application/json`
* **Body (raw JSON):**
```json
{
  "token": "9e1c3902-69ec-4581-80ec-fc8a06950294"
}
```
* **Expected Response (`200 OK`):**
```json
{
  "message": "Successfully logged out!"
}
```
* **Observation:** The `refreshToken` cookie is removed by the browser (`maxAge=0`). The refresh token is revoked in PostgreSQL, and the access token is added to the in-memory blacklist.

---

### Step 6: Verify Access Token Blacklisting
* **Method:** `GET`
* **URL:** `http://localhost:8080/api/private/user`
* **Authorization:** Select `Bearer Token`, paste the **blacklisted `accessToken` used in Step 5**.
* **Body:** None
* **Expected Response (`401 Unauthorized`):**
```json
{
  "error": "token_revoked",
  "message": "JWT token has been revoked/logged out."
}
```

---

### Step 7: Verify Replay Attack / Revoked Refresh Token Detection
* **Method:** `POST`
* **URL:** `http://localhost:8080/api/auth/refresh`
* **Headers:** `Content-Type: application/json`
* **Authorization:** `No Auth`
* **Body (raw JSON):**
```json
{
  "token": "9e1c3902-69ec-4581-80ec-fc8a06950294"
}
```
* **Expected Response (`401 Unauthorized`):**
```json
{
  "error": "unauthorized",
  "message": "Invalid refresh token: reuse detected. All sessions revoked for security"
}
```
* **Security Validation:** The system detects that a revoked token was submitted, identifies potential credential theft, and revokes all active sessions for the user.
