package com.akt.security.jwt.security;

import com.akt.security.jwt.config.SecurityProperties;
import com.akt.security.jwt.model.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.*;

@Service
public class JwtService {

    private final SecurityProperties securityProperties;
    private final SecretKey signingKey;

    public JwtService(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
        this.signingKey = getSigningKey(securityProperties);
    }

    private SecretKey getSigningKey(SecurityProperties securityProperties) {

        byte[] keyBytes = Decoders.BASE64.decode(securityProperties.getAccessToken());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {

        if (!(userDetails instanceof CustomUserDetails customUserDetails) || customUserDetails.getUser() == null) {

            throw new IllegalArgumentException("Invalid user details.");
        }

        Long userId = customUserDetails.getUser().getId();

        if (userId == null) {
            throw new IllegalStateException("User ID cannot be null.");
        }

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Map<String, Object> claims = (extraClaims != null) ? new HashMap<>(extraClaims) : new HashMap<>();
        claims.put("userId", userId);
        claims.put("roles", roles);

        Instant now = Instant.now();
        Instant expiration = now.plus(securityProperties.getAccessTokenExpiration());

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuer(securityProperties.getIssuer())
                .audience().add(securityProperties.getAudience()).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(signingKey)
                .compact();
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public List<String> extractRoles(Claims claims) {

        List<?> roles = claims.get("roles", List.class);
        if (roles == null || roles.isEmpty()) {
            return List.of();
        }
        return roles.stream()
                .map(Object::toString)
                .toList();
    }

    public Claims extractAllClaims(String token) {

        return Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(securityProperties.getIssuer())
                .requireAudience(securityProperties.getAudience())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
