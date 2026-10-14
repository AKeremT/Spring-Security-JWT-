package com.akt.security.jwt.dto;

public record LoginRequest(

        String username,
        String password
) {
}
