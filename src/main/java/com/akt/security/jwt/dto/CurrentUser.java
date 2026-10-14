package com.akt.security.jwt.dto;

import org.springframework.security.core.AuthenticatedPrincipal;

import java.util.List;

public record CurrentUser(

        Long id,
        String username,
        List<String> roles

) implements AuthenticatedPrincipal {

    @Override
    public String getName() {
        return username;
    }
}
