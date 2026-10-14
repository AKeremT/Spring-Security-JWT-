package com.akt.security.jwt.service;

import com.akt.security.jwt.config.SecurityProperties;
import com.akt.security.jwt.exception.TokenNotFoundException;
import com.akt.security.jwt.exception.TokenNotValidException;
import com.akt.security.jwt.model.RefreshToken;
import com.akt.security.jwt.model.User;
import com.akt.security.jwt.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecurityProperties securityProperties;

    public String hashToken(String token) {

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not found");
        }
    }

    public RefreshToken createRefreshToken(User user) {

        Instant now = Instant.now();
        Instant expiration = now.plus(securityProperties.getRefreshTokenExpiration());

        String rawToken = UUID.randomUUID().toString();
        String hashedToken = hashToken(rawToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(hashedToken)
                .rawToken(rawToken)
                .user(user)
                .expiryDate(expiration)
                .build();

        RefreshToken savedRefreshToken = refreshTokenRepository.save(refreshToken);
        return savedRefreshToken;
    }

    @Transactional(noRollbackFor = TokenNotValidException.class)
    public RefreshToken verifyRefreshToken(RefreshToken refreshToken) {

        if (refreshToken.isRevoked()) {

            refreshTokenRepository.revokeAllByUser(refreshToken.getUser());
            throw new TokenNotValidException("Invalid refresh token: reuse detected. All sessions revoked for security");
        }

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {

            refreshTokenRepository.delete(refreshToken);
            throw new TokenNotValidException("Refresh token has expired.");
        }
        return refreshToken;
    }

    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {

        oldToken.setRevoked(true);
        refreshTokenRepository.save(oldToken);
        return createRefreshToken(oldToken.getUser());
    }

    public Optional<RefreshToken> findByToken(String rawToken) {

        if (rawToken == null || rawToken.isEmpty()) {
            return Optional.empty();
        }
        String hashedToken = hashToken(rawToken);
        return refreshTokenRepository.findByToken(hashedToken);
    }

    public void logout(String rawToken) {

        if (rawToken == null || rawToken.isEmpty()) return;

        String hashedToken = hashToken(rawToken);
        refreshTokenRepository.findByToken(hashedToken).ifPresent(refreshToken -> {
            refreshToken.setRevoked(true);
            refreshTokenRepository.save(refreshToken);
        });
    }

    @Scheduled(cron = "@midnight")
    public void deleteExpiredRefreshTokens() {

        int deleteCount = refreshTokenRepository.deleteByExpiryDateBefore(Instant.now());
        log.info("Refresh tokens have been deleted which has expired. Deleted tokens count: {}", deleteCount);
    }
}
