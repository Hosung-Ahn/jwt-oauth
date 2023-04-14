package com.example.jwt.security.refreshtoken;


import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@RequiredArgsConstructor
@Repository
public class RefreshTokenRepository {
    private final RedisTemplate<String, String> redisTemplate;

    public void setRefreshTokenWithTimeout(String key, String value, long timeout) {
        redisTemplate.opsForValue().set(key, value, timeout);
    }

    public String getRefreshToken(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void deleteRefreshToken(String key) {
        redisTemplate.delete(key);
    }
}
