package com.security.jwtAndOauth.controller;

import com.security.jwtAndOauth.domain.Member;
import com.security.jwtAndOauth.domain.MemberDto;
import com.security.jwtAndOauth.repository.MemberRepository;
import com.security.jwtAndOauth.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final MemberService memberService;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody MemberDto memberDto) {
        Member member = new Member();
        member.setNickname(memberDto.getNickname());
        member.setEmail(memberDto.getEmail());
        member.setPassword(passwordEncoder.encode(memberDto.getPassword()));
        member.setRole(memberDto.getRole());

        ResponseEntity responseEntity = null;

        try {
            memberService.join(member);
            responseEntity = new ResponseEntity("회원가입 성공", HttpStatus.CREATED);

        } catch (Exception e) {
            responseEntity = new ResponseEntity("회원가입 실패 : " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        return responseEntity;
    }

    @RequestMapping("/user")
    public Member getUserDetailsAfterLogin(Authentication authentication) {

        if (memberRepository.existsByEmail(authentication.getName())) {
            return memberRepository.findByEmail(authentication.getName());
        } else {
            return null;
        }

    }

}
