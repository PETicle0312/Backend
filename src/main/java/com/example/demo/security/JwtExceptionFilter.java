package com.example.demo.security;

import io.jsonwebtoken.*;

import jakarta.servlet.*;
import jakarta.servlet.http.*;

import org.springframework.dao.DataAccessException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtExceptionFilter extends OncePerRequestFilter {
    private final SecurityErrors errors;

    public JwtExceptionFilter(SecurityErrors errors) {
        this.errors = errors;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        // ExceptionTranslationFilter는 뒤쪽 필터의 예외만 잡는다. JWT 필터 앞에서 별도로 감싼다.
        try {
            chain.doFilter(req, res);
        } catch (ExpiredJwtException e) {
            reject(req, res, 401, "TOKEN_EXPIRED");
        } catch (JwtException e) {
            reject(req, res, 401, "INVALID_TOKEN");
        } catch (DataAccessException e) {
            reject(req, res, 503, "AUTH_STORE_UNAVAILABLE");
        }
    }

    private void reject(HttpServletRequest q, HttpServletResponse s, int status, String code)
            throws IOException {
        SecurityContextHolder.clearContext();
        errors.write(q, s, status, code);
    }
}
