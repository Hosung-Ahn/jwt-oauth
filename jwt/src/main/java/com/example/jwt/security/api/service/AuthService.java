package com.example.jwt.security.api.service;

import com.example.jwt.security.api.dto.request.LoginDto;
import com.example.jwt.security.jwt.JwtTokenProvider;
import com.example.jwt.security.jwt.TokenDto;
import com.example.jwt.security.refreshtoken.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final RefreshTokenService refreshTokenService;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public TokenDto login(LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        TokenDto tokenDto = jwtTokenProvider.createTokens(authentication);
        refreshTokenService.setRefreshTokenWithTimeout(
                authentication.getName(), tokenDto.getRefreshToken());
        return tokenDto;
    }

    private String resolveToken(String requestAccessTokenInHeader) {
        if (requestAccessTokenInHeader != null && requestAccessTokenInHeader.startsWith("Bearer ")) {
            return requestAccessTokenInHeader.substring(7);
        } else {
            throw new IllegalArgumentException("Invalid token");
        }
    }

    @Transactional
    public void logout(String requestAccessTokenInHeader) {
        String requestAccessToken = resolveToken(requestAccessTokenInHeader);
        String email = jwtTokenProvider.getAuthentication(requestAccessToken).getName();
        refreshTokenService.deleteRefreshToken(email);
    }

    @Transactional
    public TokenDto refreshToken(String requestRefreshToken) {
        Authentication authentication = jwtTokenProvider.getAuthentication(requestRefreshToken);

        if (jwtTokenProvider.validateRefreshToken(requestRefreshToken)) {
            refreshTokenService.deleteRefreshToken(authentication.getName());
        } else {
            throw new IllegalArgumentException("Invalid token");
        }

        return jwtTokenProvider.createTokens(authentication);
    }
}
