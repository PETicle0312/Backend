package com.example.demo.security;

import com.example.demo.admin.repository.AdminRepository;
import com.example.demo.user.repository.UserRepository;

import io.jsonwebtoken.JwtException;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

@Service
public class AuthService {
    private final UserRepository users;
    private final AdminRepository admins;
    private final JwtService jwt;
    private final TokenStore store;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    private final String dummy = encoder.encode(UUID.randomUUID().toString());

    public AuthService(
            UserRepository users, AdminRepository admins, JwtService jwt, TokenStore store) {
        this.users = users;
        this.admins = admins;
        this.jwt = jwt;
        this.store = store;
    }

    public JwtService.Pair login(String id, String password, TokenRole role) {
        if (id == null
                || id.isBlank()
                || id.length() > 50
                || password == null
                || password.isBlank()
                || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new BadCredentialsException("Invalid credentials");
        }
        String hash = null;
        if (role == TokenRole.USER)
            hash = users.findByUserId(id).map(u -> u.getPassword()).orElse(null);
        if (role == TokenRole.ADMIN) {
            try {
                hash =
                        admins.findByAdminId(Long.valueOf(id))
                                .map(a -> a.getAdmPassword())
                                .orElse(null);
            } catch (NumberFormatException ignored) {
            }
        }
        boolean valid = encoder.matches(password, hash == null ? dummy : hash);
        if (!valid || hash == null) throw new BadCredentialsException("Invalid credentials");
        String sid = UUID.randomUUID().toString();
        var deadline = jwt.refreshDeadline();
        var pair = jwt.issue(id, role, sid, deadline);
        store.create(sid, hash(pair.refreshToken()), deadline);
        return pair;
    }

    public JwtService.Pair refresh(String token) {
        if (token == null || token.isBlank() || token.length() > 8192)
            throw new JwtException("Invalid refresh");
        var old = jwt.parse(token, "refresh");
        // 삭제된 계정에는 재발급하지 않는다. Role은 공개 요청 값으로 받지 않고 서명된 기존 세션에서 결정.
        boolean exists =
                old.role() == TokenRole.USER
                        ? users.existsByUserId(old.subject())
                        : admins.findByAdminId(Long.valueOf(old.subject())).isPresent();
        if (!exists) throw new JwtException("Account unavailable");
        var pair = jwt.issue(old.subject(), old.role(), old.session(), old.expiresAt());
        if (!store.rotate(old.session(), hash(token), hash(pair.refreshToken())))
            throw new JwtException("Refresh replay");
        return pair;
    }

    static String hash(String token) {
        try {
            return HexFormat.of()
                    .formatHex(
                            MessageDigest.getInstance("SHA-256")
                                    .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
