package com.example.jwt.security.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    private final long refreshTokenValidityInSeconds;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               @Value("${jwt.refresh-token-validity-in-seconds}") long refreshTokenValidityInSeconds) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenValidityInSeconds = refreshTokenValidityInSeconds;
    }

    private String getKey(String email) {
        return "AT(SERVER):" + email;
    }

    public void setRefreshTokenWithTimeout(String email, String refreshToken) {
        refreshTokenRepository.setRefreshTokenWithTimeout(getKey(email), refreshToken, refreshTokenValidityInSeconds);
    }

    public void deleteRefreshToken(String email) {
        refreshTokenRepository.deleteRefreshToken(getKey(email));
    }

    public boolean refreshTokenExists(String email) {
        return refreshTokenRepository.getRefreshToken(getKey(email)) != null;
    }

    public String getRefreshToken(String email) {
        return refreshTokenRepository.getRefreshToken(getKey(email));
    }
}
