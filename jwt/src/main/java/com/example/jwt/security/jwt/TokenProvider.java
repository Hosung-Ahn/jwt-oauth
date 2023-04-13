package com.example.jwt.security.jwt;

import com.example.jwt.security.redis.RedisService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Slf4j
public class TokenProvider implements InitializingBean {
    private final String secret;
    private final long tokenValidTimeInMilliseconds;
    private final long refreshTokenValidTimeInMilliseconds;
    private Key key;


    private final RedisService redisService;

    public TokenProvider(
            @Value("${jwt.secret}") String secret, // hmac 암호화를 사용하므로 32bit 를 넘어야한다.
            @Value("${jwt.access-token-validity-in-seconds}") long tokenValidTime,
            @Value("${jwt.refresh-token-validity-in-seconds") long refreshTokenValidTime,
            RedisService redisService) {
        this.secret = secret;
        this.tokenValidTimeInMilliseconds = tokenValidTime * 1000;
        this.refreshTokenValidTimeInMilliseconds = refreshTokenValidTime * 1000;

        this.redisService = redisService;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String createToken(Authentication authentication, boolean rememberMe) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));


        long now = (new Date()).getTime();
        Date validity;

        if (rememberMe) {
            validity = new Date(now + this.refreshTokenValidTimeInMilliseconds);
        } else {
            validity = new Date(now + this.tokenValidTimeInMilliseconds);
        }


        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("authorities", authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);

        Collection<? extends GrantedAuthority> authorities = AuthorityUtils
                .commaSeparatedStringToAuthorityList(claims.get("authorities").toString());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    //토큰 정보 Get
    public Claims getClaims(String token) {
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

    public boolean validateRefreshToken(String refreshToken) {
        try {
            if (redisService.getValue(refreshToken).equals("delete")) {
                return false;
            }
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(refreshToken);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty");
        } catch (NullPointerException e) {
            log.error("JWT Token is empty");
        }
        return false;
    }


    //access 토큰 검증(filter 에서 사용)
    public boolean validateAccessToken(String accessToken) {
        try {
            if (redisService.getValue(accessToken) != null && redisService.getValue(accessToken)
                    .equals("logout")) {
                return false;
            }
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(accessToken);
            return true;
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //재발급 검증 API 에서 사용
    public boolean validateAccessTokenOnlyExpired(String accessToken) {
        try {
            return getClaims(accessToken)
                    .getExpiration()
                    .before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
