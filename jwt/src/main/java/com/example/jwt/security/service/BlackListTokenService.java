package com.example.jwt.security.service;

import com.example.jwt.security.repository.RedisRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class BlackListTokenService {
    private final RedisRepository redisRepository;
    private final long accessTokenValidityInSeconds;

    private String getKey(String token) {
        return "blacklist_token:" + token;
    }

    public BlackListTokenService(RedisRepository redisRepository,
                                 @Value("${access-token-validity-in-seconds}")
                                 long accessTokenValidityInSeconds) {
        this.redisRepository = redisRepository;
        this.accessTokenValidityInSeconds = accessTokenValidityInSeconds;
    }

    public void setBlackListToken(String token, String status) {
        redisRepository.setWithTimeout(getKey(token), status, accessTokenValidityInSeconds);
    }

    public String getBlackListToken(String token) {
        return redisRepository.get(getKey(token));
    }

    public boolean existsByToken(String token) {
        return redisRepository.get(getKey(token)) != null;
    }
}
