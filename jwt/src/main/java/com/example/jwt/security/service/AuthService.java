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
    private final BlackListTokenService blackListTokenService;
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
    public void logout(String requestAccessTokenInHeader) {
        String accessToken = resolveToken(requestAccessTokenInHeader);
        if (!jwtValidator.validateAccessToken(accessToken)) {
            throw new IllegalArgumentException("Invalid token");
        }
        String refreshToken = accessTokenService.getRefreshToken(accessToken);
        accessTokenService.deleteAccessToken(accessToken);
        refreshTokenService.deleteRefreshToken(refreshToken);
        blackListTokenService.setBlackListToken(accessToken, "logout");
    }

    @Transactional
    public TokenDto refreshToken(String requestRefreshToken) {
        if (!jwtValidator.validateRefreshToken(requestRefreshToken)) {
            throw new IllegalArgumentException("Invalid token");
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(requestRefreshToken);
        refreshTokenService.deleteRefreshToken(requestRefreshToken);

        return jwtTokenProvider.createTokens(authentication);
    }

    public Long getMemberId(String requestAccessTokenInHeader) {
        if (!jwtValidator.validateAccessToken(resolveToken(requestAccessTokenInHeader))) {
            throw new IllegalArgumentException("Invalid token");
        }
        String requestAccessToken = resolveToken(requestAccessTokenInHeader);
        Long memberId = jwtTokenProvider.getClaims(requestAccessToken).get("memberId", Long.class);
        return memberId;
    }

    private String resolveToken(String requestAccessTokenInHeader) {
        if (requestAccessTokenInHeader != null && requestAccessTokenInHeader.startsWith("Bearer ")) {
            return requestAccessTokenInHeader.substring(7);
        } else {
            throw new IllegalArgumentException("Invalid token");
        }
    }
}
