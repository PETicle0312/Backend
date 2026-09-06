package com.example.demo.security;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService auth;
    private final TokenStore store;

    public AuthController(AuthService auth, TokenStore store) {
        this.auth = auth;
        this.store = store;
    }

    public record RefreshRequest(String refreshToken) {}

    @PostMapping("/refresh")
    public ResponseEntity<JwtService.Pair> refresh(@RequestBody RefreshRequest body) {
        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .body(auth.refresh(body.refreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Authentication authentication) {
        var identity = (JwtService.Identity) authentication.getDetails();
        store.logout(identity.session(), identity.id(), identity.expiresAt());
        return ResponseEntity.noContent().build();
    }
}
