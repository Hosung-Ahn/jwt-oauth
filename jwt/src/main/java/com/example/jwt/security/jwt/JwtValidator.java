package com.example.jwt.security.jwt;

import com.example.jwt.security.blacklisttoken.BlackListTokenService;
import com.example.jwt.security.refreshtoken.RefreshTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtValidator {
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final BlackListTokenService blackListTokenService;

    public boolean validateToken(String authToken) {
        try {
            jwtTokenProvider.getClaims(authToken);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT signature.");
            log.trace("Invalid JWT signature trace: {}", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            log.trace("Expired JWT token trace: {}", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            log.trace("Unsupported JWT token trace: {}", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            log.trace("JWT token compact of handler are invalid trace: {}", e);
        }
        return false;
    }

    public boolean validateRefreshToken(String refreshToken) {
        if (!validateToken(refreshToken) ||
                !refreshTokenService.existsByEmail(jwtTokenProvider.getClaims(refreshToken).getSubject())) {
            return false;
        }
        return true;
    }

    public boolean validateAccessToken(String accessToken) {
        // AT는 filter 에서 validateToken 을 이미 통과함
        if (blackListTokenService.existsByToken(accessToken)) {
            return false;
        }
        return true;
    }
}
