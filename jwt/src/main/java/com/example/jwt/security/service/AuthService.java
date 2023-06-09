package com.example.jwt.security.service;

import com.example.jwt.security.dto.request.LoginDto;
import com.example.jwt.security.jwt.JwtTokenProvider;
import com.example.jwt.security.jwt.JwtValidator;
import com.example.jwt.security.jwt.TokenDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final RefreshTokenService refreshTokenService;
    private final AccessTokenService accessTokenService;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final JwtValidator jwtValidator;

    @Transactional
    public TokenDto login(LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return jwtTokenProvider.createTokens(authentication);
    }

    @Transactional
    public void logout(String accessTokenInHeader) {
        String accessToken = resolveToken(accessTokenInHeader);
        if (!jwtValidator.validateAccessToken(accessToken)) {
            throw new IllegalArgumentException("Invalid token");
        }
        String refreshToken = accessTokenService.getAccessToken(accessToken);
        accessTokenService.deleteAccessToken(accessToken);
        refreshTokenService.deleteRefreshToken(refreshToken);
    }

    @Transactional
    public TokenDto refresh(String refreshToken) {
        if (!jwtValidator.validateRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid token");
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);

        String accessToken = refreshTokenService.getRefreshToken(refreshToken);
        accessTokenService.deleteAccessToken(accessToken);
        refreshTokenService.deleteRefreshToken(refreshToken);
        return jwtTokenProvider.createTokens(authentication);
    }


    public Long getMemberId(String accessTokenInHeader) {
        if (!jwtValidator.validateAccessToken(resolveToken(accessTokenInHeader))) {
            throw new IllegalArgumentException("Invalid token");
        }
        String accessToken = resolveToken(accessTokenInHeader);
        Long memberId = jwtTokenProvider.getClaims(accessToken).get("memberId", Long.class);
        return memberId;
    }

    private String resolveToken(String accessTokenInHeader) {
        if (accessTokenInHeader != null && accessTokenInHeader.startsWith("Bearer ")) {
            return accessTokenInHeader.substring(7);
        } else {
            throw new IllegalArgumentException("Invalid token");
        }
    }
}
