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



    @BeforeEach
    void beforeEach() {
        memberRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        blackListTokenRepository.deleteAll();
    }


    @Test
    void register() {
        Member member = new Member();
        member.setEmail("test@example.com");
        member.setPassword(passwordEncoder.encode("password"));
        member.setAdmin(false);
        memberService.register(member);

        Member findMember = memberRepository.findByEmail("test@example.com").get();

        Assertions.assertThat(findMember).isEqualTo(member);
    }

    @Test
    void login() {
        Member member = new Member();
        member.setEmail("test@example.com");
        member.setPassword(passwordEncoder.encode("password"));
        member.setAdmin(false);
        memberService.register(member);

        LoginDto loginDto = new LoginDto("test@example.com", "password");

        TokenDto tokenDto = authService.login(loginDto);
        assertNotNull(tokenDto);
        assertNotNull(tokenDto.getAccessToken());
        assertNotNull(tokenDto.getRefreshToken());

        System.out.println("tokenDto.getAccessToken() = " + tokenDto.getAccessToken());
        System.out.println("tokenDto.getRefreshToken() = " + tokenDto.getRefreshToken());
    }


}