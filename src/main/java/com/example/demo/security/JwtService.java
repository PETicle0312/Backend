package com.example.demo.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.*;
import java.util.*;

import javax.crypto.SecretKey;

@Service
public class JwtService {
    private final SecretKey key;
    private final String issuer;
    private final Duration accessTtl, refreshTtl;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.issuer:peticle}") String issuer,
            @Value("${security.jwt.access-ttl:PT15M}") Duration accessTtl,
            @Value("${security.jwt.refresh-ttl:P7D}") Duration refreshTtl) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.issuer = issuer;
        this.accessTtl = accessTtl;
        this.refreshTtl = refreshTtl;
        if (accessTtl.compareTo(Duration.ofSeconds(1)) < 0 || refreshTtl.compareTo(accessTtl) <= 0)
            throw new IllegalArgumentException("Invalid token TTL configuration");
    }

    public record Pair(String accessToken, String refreshToken, long expiresIn, String tokenType) {}

    public record Identity(
            String subject, TokenRole role, String session, String id, Instant expiresAt) {}

    public Pair issue(String subject, TokenRole role, String session, Instant refreshDeadline) {
        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Instant deadline = refreshDeadline.truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        if (!deadline.isAfter(now)) throw new ExpiredJwtException(null, null, "Session expired");
        // 패밀리 폐기 키가 사라진 뒤 AccessToken만 살아나는 경계 오류를 방지한다.
        Instant accessExpiry =
                now.plus(accessTtl).isBefore(deadline) ? now.plus(accessTtl) : deadline;
        return new Pair(
                sign(subject, role, session, "access", accessExpiry),
                sign(subject, role, session, "refresh", deadline),
                Duration.between(now, accessExpiry).toSeconds(),
                "Bearer");
    }

    public Instant refreshDeadline() {
        return Instant.now().plus(refreshTtl).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    }

    private String sign(
            String subject, TokenRole role, String session, String type, Instant expiry) {
        return Jwts.builder()
                .issuer(issuer)
                .subject(subject)
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date())
                .expiration(Date.from(expiry))
                .claim("role", role.name())
                .claim("sid", session)
                .claim("type", type)
                .audience()
                .add("peticle-api")
                .and()
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public Identity parse(String token, String type) {
        if (token == null || token.isBlank()) throw new JwtException("Empty token");
        var signed =
                Jwts.parser()
                        .verifyWith(key)
                        .requireIssuer(issuer)
                        .requireAudience("peticle-api")
                        .require("type", type)
                        .build()
                        .parseSignedClaims(token);
        Claims c = signed.getPayload();
        if (!"HS256".equals(signed.getHeader().getAlgorithm())
                || c.getExpiration() == null
                || c.getSubject() == null
                || c.getSubject().isBlank()
                || c.getId() == null
                || c.get("sid", String.class) == null) throw new JwtException("Invalid claims");
        try {
            UUID.fromString(c.getId());
            UUID.fromString(c.get("sid", String.class));
            return new Identity(
                    c.getSubject(),
                    TokenRole.valueOf(c.get("role", String.class)),
                    c.get("sid", String.class),
                    c.getId(),
                    c.getExpiration().toInstant());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new JwtException("Invalid identity", e);
        }
    }
}
