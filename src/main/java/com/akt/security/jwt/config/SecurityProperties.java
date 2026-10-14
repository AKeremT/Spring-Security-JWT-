package com.akt.security.jwt.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class SecurityProperties {

    private String accessToken;
    private Duration accessTokenExpiration;
    private Duration refreshTokenExpiration;
    private String issuer;
    private String audience;
}
