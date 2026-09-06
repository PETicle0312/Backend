package com.example.demo.security;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.*;

import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Component
public class SecurityErrors {
    private final ObjectMapper mapper;

    public SecurityErrors(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public void write(HttpServletRequest req, HttpServletResponse res, int status, String code)
            throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        res.setHeader("Cache-Control", "no-store");
        if (status == 401) res.setHeader("WWW-Authenticate", "Bearer");
        mapper.writeValue(
                res.getOutputStream(),
                Map.of(
                        "status",
                        status,
                        "code",
                        code,
                        "path",
                        req.getRequestURI(),
                        "timestamp",
                        Instant.now().toString()));
    }

    public AuthenticationEntryPoint entryPoint() {
        return (q, s, e) -> write(q, s, 401, "UNAUTHENTICATED");
    }

    public AccessDeniedHandler deniedHandler() {
        return (q, s, e) -> write(q, s, 403, "ACCESS_DENIED");
    }
}
