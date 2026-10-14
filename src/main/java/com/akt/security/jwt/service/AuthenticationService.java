package com.akt.security.jwt.service;

import com.akt.security.jwt.dto.AuthResponse;
import com.akt.security.jwt.dto.LoginRequest;
import com.akt.security.jwt.dto.RefreshTokenRequest;
import com.akt.security.jwt.dto.RegisterRequest;
import com.akt.security.jwt.exception.TokenNotFoundException;
import com.akt.security.jwt.exception.TokenNotValidException;
import com.akt.security.jwt.exception.UserAlreadyExistsException;
import com.akt.security.jwt.model.CustomUserDetails;
import com.akt.security.jwt.model.RefreshToken;
import com.akt.security.jwt.model.Role;
import com.akt.security.jwt.model.User;
import com.akt.security.jwt.repository.UserRepository;
import com.akt.security.jwt.security.JwtService;
import com.akt.security.jwt.security.TokenBlackListService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenBlackListService tokenBlackListService;

    public AuthResponse register(RegisterRequest registerRequest) {

        if (userRepository.findByUsername(registerRequest.username()).isPresent()) {
            throw new UserAlreadyExistsException("User already exists with: " + registerRequest.username());
        }

        User user = User.builder()
                .username(registerRequest.username())
                .password(passwordEncoder.encode(registerRequest.password()))
                .email(registerRequest.email())
                .roles(Set.of(Role.USER))
                .build();
        User savedUser = userRepository.save(user);
        String accessToken = jwtService.generateToken(new CustomUserDetails(savedUser));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(savedUser);

        return new AuthResponse(accessToken, refreshToken.getRawToken());
    }

    public AuthResponse login(LoginRequest loginRequest) {

        var authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));

        CustomUserDetails customUserDetails = (CustomUserDetails) Objects.requireNonNull(authentication.getPrincipal());

        String accessToken = jwtService.generateToken(customUserDetails);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(customUserDetails.getUser());
        return new AuthResponse(accessToken, refreshToken.getRawToken());
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {

        RefreshToken refreshToken = refreshTokenService.findByToken(request.token())
                .map(refreshTokenService::verifyRefreshToken)
                .orElseThrow(() -> new TokenNotFoundException("Refresh token not found"));

        User user = refreshToken.getUser();

        if (!user.isEnabled() || !user.isAccountNonLocked()) {
            throw new TokenNotValidException("User account is locked or disabled");
        }

        String accessToken = jwtService.generateToken(new CustomUserDetails(user));
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken);
        return new AuthResponse(accessToken, newRefreshToken.getRawToken());
    }

    public void logout(String accessToken, RefreshTokenRequest refreshTokenRequest) {

        if (refreshTokenRequest != null && refreshTokenRequest.token() != null && !refreshTokenRequest.token().isBlank()) {
            refreshTokenService.logout(refreshTokenRequest.token());
        }

        if (accessToken != null && !accessToken.isBlank()) {

            try {
                Claims claims = jwtService.extractAllClaims(accessToken);
                Instant expiration = claims.getExpiration().toInstant();
                tokenBlackListService.blacklistToken(accessToken, expiration);
            } catch (JwtException | IllegalArgumentException e) {}
        }
        SecurityContextHolder.clearContext();
    }
}
