package com.akt.security.jwt.dto;

public record RegisterRequest(

        String username,
        String password,
        String email
) {
}
