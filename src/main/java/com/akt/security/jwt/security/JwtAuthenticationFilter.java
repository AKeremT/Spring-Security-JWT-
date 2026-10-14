package com.akt.security.jwt.security;

import com.akt.security.jwt.dto.CurrentUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenBlackListService tokenBlackListService;
    private final JwtService jwtService;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private void writeErrorResponse(HttpServletResponse response, int status, String error, String message) throws IOException {

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        Map<String, String> body = Map.of("error", error, "message", message);
        objectMapper.writeValue(response.getWriter(), body);
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getServletPath();
        return path.equals("/api/auth") || path.equals("/api/auth/register") || path.equals("/api/auth/login") || path.equals("/api/auth/refresh");
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authToken = authHeader.substring(7);

        try {

            if (tokenBlackListService.isTokenBlacklisted(authToken)) {

                log.warn("Access Denied: Revoked token used for request UR: {}", request.getRequestURI());
                writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "token_revoked", "JWT token has been revoked/logged out.");
                return;
            }

            Claims claims = jwtService.extractAllClaims(authToken);
            String username = claims.getSubject();

            if (StringUtils.hasText(username) && SecurityContextHolder.getContext().getAuthentication() == null) {

                Long userId = claims.get("userId", Long.class);
                List<String> roles = jwtService.extractRoles(claims);

                CurrentUser currentUser = new CurrentUser(userId, username, roles);

                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                UsernamePasswordAuthenticationToken authentication
                        = new UsernamePasswordAuthenticationToken(currentUser, null, authorities);

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("Authentication Success: {}", authentication);
            }
        } catch (ExpiredJwtException e) {
            log.warn("JWT token has expired: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "token_expired", "JWT token has expired.");
            return;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "token_invalid", "JWT token is invalid.");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
