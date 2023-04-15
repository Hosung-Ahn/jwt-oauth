package com.example.jwt.security.refreshtoken;

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
        return "RT(SERVER):" + email;
    }

    public void setRefreshTokenWithTimeout(String email, String refreshToken) {
        refreshTokenRepository.setWithTimeout(getKey(email), refreshToken, refreshTokenValidityInSeconds);
    }

    public void deleteRefreshToken(String email) {
        refreshTokenRepository.delete(getKey(email));
    }

    public boolean existsByEmail(String email) {
        return refreshTokenRepository.get(getKey(email)) != null;
    }

}
