package com.example.jwt.security.api.service;

import com.example.jwt.domain.Member;
import com.example.jwt.repository.MemberRepository;
import com.example.jwt.security.api.dto.request.LoginDto;
import com.example.jwt.security.blacklisttoken.BlackListTokenRepository;
import com.example.jwt.security.jwt.JwtValidator;
import com.example.jwt.security.jwt.TokenDto;
import com.example.jwt.security.refreshtoken.RefreshTokenRepository;
import com.example.jwt.service.MemberService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
class AuthServiceTest {

    @Autowired
    private AuthService authService;
    @Autowired
    private MemberService memberService;
    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private BlackListTokenRepository blackListTokenRepository;
    @Autowired
    private JwtValidator jwtValidator;



    @BeforeEach
    void beforeEach() {
        memberRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        blackListTokenRepository.deleteAll();

        Member member = new Member();
        member.setEmail("test@example.com");
        member.setPassword(passwordEncoder.encode("password"));
        member.setAdmin(false);
        memberService.register(member);
    }


    @Test
    void register() {
        Member member1 = new Member();
        member1.setEmail("test2@example.com");
        member1.setPassword(passwordEncoder.encode("password"));
        member1.setAdmin(false);
        memberService.register(member1);

        Member findMember = memberRepository.findByEmail("test2@example.com").get();

        Assertions.assertThat(findMember).isEqualTo(member1);
    }

    @Test
    void login() {
        LoginDto loginDto = new LoginDto("test@example.com", "password");

        TokenDto tokenDto = authService.login(loginDto);

        jwtValidator.validateToken(tokenDto.getAccessToken());
        jwtValidator.validateAccessToken(tokenDto.getAccessToken());
        jwtValidator.validateToken(tokenDto.getRefreshToken());
        jwtValidator.validateRefreshToken(tokenDto.getRefreshToken());


        System.out.println("tokenDto.getAccessToken() = " + tokenDto.getAccessToken());
        System.out.println("tokenDto.getRefreshToken() = " + tokenDto.getRefreshToken());
    }

    @Test
    void logout() {
        LoginDto loginDto = new LoginDto("test@example.com", "password");
        TokenDto tokenDto = authService.login(loginDto);

        authService.logout("Bearer " + tokenDto.getAccessToken());

        Assertions.assertThat(blackListTokenRepository.get(tokenDto.getAccessToken())).isEqualTo("logout");
    }

    @Test
    void refresh() {
        LoginDto loginDto = new LoginDto("test@example.com", "password");
        TokenDto tokenDto = authService.login(loginDto);

        TokenDto tokenDto1 = authService.refreshToken(tokenDto.getRefreshToken());

        jwtValidator.validateToken(tokenDto.getAccessToken());
        jwtValidator.validateAccessToken(tokenDto.getAccessToken());
        jwtValidator.validateToken(tokenDto.getRefreshToken());
        jwtValidator.validateRefreshToken(tokenDto.getRefreshToken());
    }
}