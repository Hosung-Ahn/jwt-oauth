package com.example.jwt.security.service;

import com.example.jwt.security.repository.RedisRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AccessTokenService {
    private final RedisRepository redisRepository;
    private final long accessTokenValidityInSeconds;

    public AccessTokenService(RedisRepository redisRepository,
                              @Value("${access-token-validity-in-seconds}")
                              long accessTokenValidityInSeconds) {
        this.redisRepository = redisRepository;
        this.accessTokenValidityInSeconds = accessTokenValidityInSeconds;
    }

    private String getKey(String token) {
        return "access_token:" + token;
    }

    public void setAccessTokenWithRefreshToken(String accessToken, String refreshToken) {
        redisRepository.setWithTimeout(getKey(accessToken), refreshToken,
                accessTokenValidityInSeconds);
    }

    public String getRefreshToken(String accessToken) {
        return redisRepository.get(getKey(accessToken));
    }

    public void deleteAccessToken(String accessToken) {
        redisRepository.delete(getKey(accessToken));
    }
    public boolean existsByToken(String accessToken) {
        return redisRepository.get(getKey(accessToken)) != null;
    }
}
