package com.example.jwt.security.jwt;

import com.example.jwt.repository.MemberRepository;
import com.example.jwt.security.refreshtoken.RefreshTokenRepository;
import com.example.jwt.security.refreshtoken.RefreshTokenService;
import com.example.jwt.security.userdetails.MemberDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenProvider implements InitializingBean {
    private final String secret;
    private final long tokenValidTimeInMilliseconds;
    private final long refreshTokenValidTimeInMilliseconds;
    private Key key;

    private final RefreshTokenService refreshTokenService;

    private final MemberRepository memberRepository;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret, // hmac 암호화를 사용하므로 32bit 를 넘어야한다.
            @Value("${jwt.access-token-validity-in-seconds}") long tokenValidTime,
            @Value("${jwt.refresh-token-validity-in-seconds}") long refreshTokenValidTime,
            RefreshTokenRepository refreshTokenRepository, RefreshTokenService refreshTokenService,
            MemberRepository memberRepository) {
        this.secret = secret;
        this.tokenValidTimeInMilliseconds = tokenValidTime * 1000;
        this.refreshTokenValidTimeInMilliseconds = refreshTokenValidTime * 1000;
        this.refreshTokenService = refreshTokenService;
        this.memberRepository = memberRepository;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String createToken(Authentication authentication, boolean rememberMe) {
        MemberDetails memberDetails = (MemberDetails) authentication.getPrincipal();

        long now = (new Date()).getTime();
        Date validity;

        if (rememberMe) {
            validity = new Date(now + this.refreshTokenValidTimeInMilliseconds);
        } else {
            validity = new Date(now + this.tokenValidTimeInMilliseconds);
        }

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("memberId", memberDetails.getMemberId())
                .claim("authorities", memberDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.joining(",")))
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

    public TokenDto createTokens(Authentication authentication) {
        String accessToken = createToken(authentication, false);
        String refreshToken = createToken(authentication, true);

        return new TokenDto(accessToken, refreshToken);
    }


    @Transactional
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);

        Collection<? extends GrantedAuthority> authorities = AuthorityUtils
                .commaSeparatedStringToAuthorityList(claims.get("authorities").toString());

        Long memberId = claims.get("memberId", Long.class); // Add this line

        MemberDetails principal = new MemberDetails(memberRepository.findById(memberId)
                .orElseThrow(
                        () -> new IllegalArgumentException("해당 사용자가 없습니다. id=" + memberId)
                )
        );

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }


    private Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    //access 토큰 검증(filter 에서 사용)
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(authToken);
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
                getClaims(refreshToken).getExpiration().before(new Date()) ||
                !refreshTokenService.existsByEmail(getClaims(refreshToken).getSubject())
        ) return false;
        return true;
    }
}
