package com.akt.security.jwt.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(TokenNotValidException.class)
    public ResponseEntity<Map<String, String>> handleTokenNotValidException(TokenNotValidException ex) {

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                Map.of("error", "unauthorized", "message", ex.getMessage()));
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<Map<String, String>> handleUserAlreadyExistsException(UserAlreadyExistsException ex) {

        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                Map.of("error", "conflict", "message", ex.getMessage()));
    }

    @ExceptionHandler(TokenNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleTokenNotFoundException(TokenNotFoundException ex) {

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                Map.of("error", "unauthorized", "message", ex.getMessage()));
    }
}
