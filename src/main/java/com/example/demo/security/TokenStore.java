package com.example.demo.security;

import java.time.Instant;

public interface TokenStore {
    void create(String session, String refreshHash, Instant deadline);

    boolean rotate(String session, String oldHash, String newHash);

    boolean blocked(String session, String accessId);

    void logout(String session, String accessId, Instant accessExpiry);
}
