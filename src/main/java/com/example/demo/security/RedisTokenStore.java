package com.example.demo.security;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Repository;

import java.time.*;
import java.util.List;

@Repository
public class RedisTokenStore implements TokenStore {
    private final StringRedisTemplate redis;

    public RedisTokenStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    // 같은 {sid} 해시 태그: Redis Cluster에서도 모든 스크립트 키는 같은 슬롯.
    private String key(String sid, String suffix) {
        return "auth:{" + sid + "}:" + suffix;
    }

    public void create(String sid, String hash, Instant deadline) {
        if (!Boolean.TRUE.equals(
                redis.opsForValue()
                        .setIfAbsent(
                                key(sid, "refresh"),
                                hash,
                                Duration.ofMillis(
                                        Math.max(
                                                1,
                                                Duration.between(Instant.now(), deadline)
                                                        .toMillis())))))
            throw new IllegalStateException("Session collision");
    }

    private static final DefaultRedisScript<Long> ROTATE =
            new DefaultRedisScript<>(
                    """
                    local current = redis.call('GET', KEYS[1])
                    if not current or redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
                    if current ~= ARGV[1] then
                        local ttl = redis.call('PTTL', KEYS[1])
                        if ttl > 0 then redis.call('SET', KEYS[2], '1', 'PX', ttl) end
                        redis.call('DEL', KEYS[1])
                        return 0
                    end
                    redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
                    return 1
                    """,
                    Long.class);

    // GET→비교→SET을 Java에서 분리하지 않는다. 회전과 재사용 탐지/패밀리 폐기를 원자화한다.
    public boolean rotate(String sid, String oldHash, String newHash) {
        return Long.valueOf(1)
                .equals(
                        redis.execute(
                                ROTATE,
                                List.of(key(sid, "refresh"), key(sid, "revoked")),
                                oldHash,
                                newHash));
    }

    public boolean blocked(String sid, String id) {
        return !Boolean.TRUE.equals(redis.hasKey(key(sid, "refresh")))
                || Boolean.TRUE.equals(redis.hasKey(key(sid, "blacklist:" + id)))
                || Boolean.TRUE.equals(redis.hasKey(key(sid, "revoked")));
    }

    private static final DefaultRedisScript<Long> LOGOUT =
            new DefaultRedisScript<>(
                    """
local ttl = math.max(redis.call('PTTL', KEYS[1]), redis.call('PTTL', KEYS[2]), tonumber(ARGV[1]))
if ttl > 0 then redis.call('SET', KEYS[2], '1', 'PX', ttl) end
if tonumber(ARGV[1]) > 0 then redis.call('SET', KEYS[3], '1', 'PX', ARGV[1]) end
redis.call('DEL', KEYS[1])
return 1
""",
                    Long.class);

    public void logout(String sid, String id, Instant expiry) {
        redis.execute(
                LOGOUT,
                List.of(key(sid, "refresh"), key(sid, "revoked"), key(sid, "blacklist:" + id)),
                Long.toString(Math.max(1, Duration.between(Instant.now(), expiry).toMillis())));
    }
}
