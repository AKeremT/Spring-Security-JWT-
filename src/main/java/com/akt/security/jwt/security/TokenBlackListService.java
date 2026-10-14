package com.akt.security.jwt.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class TokenBlackListService {

    private final Map<String, Instant> blacklistedTokens = new ConcurrentHashMap<>();

    public void blacklistToken(String token, Instant expiration) {

        if (token != null && expiration != null && expiration.isAfter(Instant.now())) {
            blacklistedTokens.put(token, expiration);
            log.info("Access token blacklisted. Expiration date: {}", expiration);
        }
    }

    public boolean isTokenBlacklisted(String token) {

        if (token == null) return false;
        Instant expiration = blacklistedTokens.get(token);
        if (expiration == null) return false;
        if (expiration.isBefore(Instant.now())) {
            blacklistedTokens.remove(token);
            return false;
        }
        return true;
    }

    @Scheduled(fixedDelay = 15, timeUnit = TimeUnit.MINUTES)
    public void cleanupExpiredBlacklist(){

        blacklistedTokens.entrySet().removeIf(entry -> entry.getValue().isBefore(Instant.now()));
        log.info("Cleanup expired blacklisted tokens");
    }
}
