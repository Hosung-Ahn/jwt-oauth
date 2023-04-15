package com.example.jwt.security.service;

import com.example.jwt.security.repository.RedisRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class RefreshTokenService {
    private final RedisRepository redisRepository;

    private final long refreshTokenValidityInSeconds;

    public RefreshTokenService(RedisRepository redisRepository,
                               @Value("${jwt.refresh-token-validity-in-seconds}")
                               long refreshTokenValidityInSeconds) {
        this.redisRepository = redisRepository;
        this.refreshTokenValidityInSeconds = refreshTokenValidityInSeconds;
    }

    private String getKey(String token) {
        return "refresh_token:" + token;
    }

    public void setRefreshTokenWithTimeout(String token, String status) {
        redisRepository.setWithTimeout(getKey(token), status, refreshTokenValidityInSeconds);
    }

    public void deleteRefreshToken(String token) {
        redisRepository.delete(getKey(token));
    }

    public boolean isActive(String token) {
        return redisRepository.get(getKey(token)).equals("active");
    }

}
