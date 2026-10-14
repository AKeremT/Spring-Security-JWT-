package com.akt.security.jwt.dto;

public record AuthResponse(

        String accessToken,
        String refreshToken
) {
}
