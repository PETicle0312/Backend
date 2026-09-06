package com.example.demo.security;

import java.util.List;

public enum TokenRole {
    USER(List.of("ROLE_USER", "user:read", "user:write", "game:play", "open:read")),
    ADMIN(
            List.of(
                    "ROLE_ADMIN",
                    "admin:read",
                    "admin:write",
                    "device:read",
                    "device:write",
                    "open:read"));
    private final List<String> authorities;

    TokenRole(List<String> authorities) {
        this.authorities = authorities;
    }

    public List<String> authorities() {
        return authorities;
    }
}
