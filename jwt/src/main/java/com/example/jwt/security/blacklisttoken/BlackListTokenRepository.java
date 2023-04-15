package com.example.jwt.security.blacklisttoken;

import com.example.jwt.security.refreshtoken.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;


@Repository
public class BlackListTokenRepository extends RefreshTokenRepository {
    public BlackListTokenRepository(RedisTemplate<String, String> redisTemplate) {
        super(redisTemplate);
    }
}
