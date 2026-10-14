package com.akt.security.jwt.controller;

import com.akt.security.jwt.config.SecurityProperties;
import com.akt.security.jwt.dto.AuthResponse;
import com.akt.security.jwt.dto.LoginRequest;
import com.akt.security.jwt.dto.RefreshTokenRequest;
import com.akt.security.jwt.dto.RegisterRequest;
import com.akt.security.jwt.exception.TokenNotFoundException;
import com.akt.security.jwt.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;
    private final SecurityProperties securityProperties;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest registerRequest) {

        AuthResponse authResponse = authenticationService.register(registerRequest);
        ResponseCookie cookie = createRefreshTokenCookie(authResponse.refreshToken(), securityProperties.getRefreshTokenExpiration());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(authResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest) {

        AuthResponse authResponse = authenticationService.login(loginRequest);
        ResponseCookie cookie = createRefreshTokenCookie(authResponse.refreshToken(), securityProperties.getRefreshTokenExpiration());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(authResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @CookieValue(name = "refreshToken", required = false) String cookieRefreshToken,
            @RequestBody(required= false) RefreshTokenRequest refreshTokenRequest) {

        String token = (cookieRefreshToken != null && !cookieRefreshToken.isBlank())
                ? cookieRefreshToken
                : (refreshTokenRequest != null ? refreshTokenRequest.token() : null);

        if (token == null || token.isBlank()) {
            throw new TokenNotFoundException("Refresh token is missing");
        }

        AuthResponse authResponse = authenticationService.refreshToken(new RefreshTokenRequest(token));
        ResponseCookie cookie = createRefreshTokenCookie(authResponse.refreshToken(), securityProperties.getRefreshTokenExpiration());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(authResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader(name = "Authorization", required = false) String authHeader,
            @CookieValue(name = "refreshToken", required = false) String cookieRefreshToken,
            @RequestBody(required= false) RefreshTokenRequest refreshTokenRequest) {

        String accessToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);
        }

        String refreshToken = (cookieRefreshToken != null && !cookieRefreshToken.isBlank())
                ? cookieRefreshToken
                : (refreshTokenRequest != null ? refreshTokenRequest.token() : null);

        authenticationService.logout(accessToken, refreshToken != null ? new RefreshTokenRequest(refreshToken) : null);

        ResponseCookie cleanCookie = cleanRefreshTokenCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(Map.of("message", "Successfully logged out!"));
    }

    private ResponseCookie createRefreshTokenCookie(String token, Duration maxAge) {

        return ResponseCookie.from("refreshToken", token)
                .httpOnly(true) // Security for XSS attacks
                .secure(false) // true with https
                .sameSite("Strict") // Security for CSRF attacks
                .path("/api/auth")
                .maxAge(maxAge)
                .build();
    }

    private ResponseCookie cleanRefreshTokenCookie() {

        return ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Strict")
                .path("/api/auth")
                .maxAge(0)
                .build();
    }

    @GetMapping
    public String hello(){
        return "Hello from auth controller";
    }


}
