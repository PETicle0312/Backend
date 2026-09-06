package com.example.demo.security;

import io.jsonwebtoken.*;

import jakarta.servlet.http.*;

import org.springframework.dao.DataAccessException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestControllerAdvice
public class AuthExceptionAdvice {
    private final SecurityErrors errors;

    public AuthExceptionAdvice(SecurityErrors errors) {
        this.errors = errors;
    }

    @ExceptionHandler(AuthenticationException.class)
    void credentials(HttpServletRequest q, HttpServletResponse s) throws IOException {
        errors.write(q, s, 401, "UNAUTHENTICATED");
    }

    @ExceptionHandler(JwtException.class)
    void token(JwtException e, HttpServletRequest q, HttpServletResponse s) throws IOException {
        errors.write(
                q, s, 401, e instanceof ExpiredJwtException ? "TOKEN_EXPIRED" : "INVALID_TOKEN");
    }

    @ExceptionHandler(DataAccessException.class)
    void storage(HttpServletRequest q, HttpServletResponse s) throws IOException {
        errors.write(q, s, 503, "AUTH_STORE_UNAVAILABLE");
    }
}
