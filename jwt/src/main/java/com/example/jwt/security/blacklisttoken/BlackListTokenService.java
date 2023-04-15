package com.example.jwt.security.blacklisttoken;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class BlackListTokenService {
    private final BlackListTokenRepository blackListTokenRepository;
    private final long blackListTokenValidityInSeconds;

    public BlackListTokenService(BlackListTokenRepository blackListTokenRepository,
                                 @Value("${jwt.refresh-token-validity-in-seconds}")
                                 long blackListTokenValidityInSeconds) {
        this.blackListTokenRepository = blackListTokenRepository;
        this.blackListTokenValidityInSeconds = blackListTokenValidityInSeconds;
    }

    public void setBlackListToken(String token, String value) {
        blackListTokenRepository.setWithTimeout("BlackList:" + token, value, blackListTokenValidityInSeconds);
    }

    public String getBlackListToken(String token) {
        return blackListTokenRepository.get(token);
    }

    public boolean existsByToken(String token) {
        return blackListTokenRepository.get(token) != null;
    }
}
