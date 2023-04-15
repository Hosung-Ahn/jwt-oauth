package com.example.jwt.security.refreshtoken;


import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
@Repository
public class RefreshTokenRepository {
    private final RedisTemplate<String, String> redisTemplate;

    public void setWithTimeout(String key, String value, long timeout) {
        redisTemplate.opsForValue().set(key, value, timeout, TimeUnit.SECONDS);
    }

    public String get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void delete(String key) {
        redisTemplate.delete(key);
    }

    // test 용
    public void deleteAll() {
        redisTemplate.delete(redisTemplate.keys("*"));
    }
}
