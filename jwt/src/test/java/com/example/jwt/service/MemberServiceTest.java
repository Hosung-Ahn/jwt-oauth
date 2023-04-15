package com.example.jwt.service;

import com.example.jwt.domain.Member;
import com.example.jwt.repository.MemberRepository;
import com.example.jwt.security.dto.request.LoginDto;
import com.example.jwt.security.dto.request.SignupDto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;


@SpringBootTest
@Transactional
class MemberServiceTest {
    @Autowired
    private MemberService memberService;
    @Autowired
    private MemberRepository memberRepository;

    @BeforeEach
    void beforeEach() {
        memberRepository.deleteAll();
    }

    @Test
    void registerUser() {
        SignupDto signupDto = new SignupDto();
        signupDto.setNickname("test");
        signupDto.setEmail("test@com");
        signupDto.setPassword("password");
        Member user = memberService.createUser(signupDto);

        memberService.register(user);
        Member findMember = memberRepository.findByEmail("test@com").get();
        assertThat(findMember).isSameAs(user);
    }

    @Test
    void notRegisterUser() {
        SignupDto signupDto = new SignupDto();
        signupDto.setNickname("test");
        signupDto.setEmail("test@com");
        signupDto.setPassword("password");
        Member user = memberService.createUser(signupDto);

        memberService.register(user);

        assertThrows(NoSuchElementException.class, () -> {
            memberRepository.findByEmail("test1@com").get();
        });
    }

    @Test
    void registerDuplicateUser() {
        SignupDto signupDto = new SignupDto();
        signupDto.setNickname("test");
        signupDto.setEmail("test@com");
        signupDto.setPassword("password");
        Member user = memberService.createUser(signupDto);

        memberService.register(user);

        assertThrows(IllegalStateException.class, () -> {
            memberService.register(user);
        });
        
    }
}