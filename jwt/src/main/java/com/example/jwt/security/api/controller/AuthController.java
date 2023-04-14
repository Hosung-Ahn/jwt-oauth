package com.example.jwt.security.api.controller;

import com.example.jwt.domain.Authority;
import com.example.jwt.domain.Member;
import com.example.jwt.mapper.MemberMapper;
import com.example.jwt.repository.MemberRepository;
import com.example.jwt.security.api.dto.request.LoginDto;
import com.example.jwt.security.api.dto.request.SignupDto;
import com.example.jwt.security.api.service.AuthService;
import com.example.jwt.security.jwt.TokenDto;
import com.example.jwt.service.MemberService;
import io.lettuce.core.dynamic.annotation.Param;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthService authService;
    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;

    // 테스트
    private final MemberRepository memberRepository;

    @PostMapping("/signup")
    public ResponseEntity signup(@Valid @RequestBody SignupDto signupDto) {
        Member member = MemberMapper.INSTANCE.toMember(signupDto);
        log.info("{}", member);
        member.setPassword(passwordEncoder.encode(member.getPassword()));
        member.setAdmin(false);

        ResponseEntity responseEntity = null;
        try {
            memberService.join(member);
            responseEntity = new ResponseEntity("회원가입 성공", HttpStatus.CREATED);

        } catch (Exception e) {
            responseEntity = new ResponseEntity("회원가입 실패 : " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        return responseEntity;
    }

    @PostMapping("/login")
    public ResponseEntity login(@Valid @RequestBody LoginDto loginDto) {
        TokenDto tokenDto = authService.login(loginDto);
        HttpCookie httpCookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenDto.getAccessToken())
                .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                .body("login success");
    }

    @GetMapping("/mypage")
    public String mypage(@Param("memberId") Long memberId) {
        return memberRepository.findById(memberId).toString();
    }
}
