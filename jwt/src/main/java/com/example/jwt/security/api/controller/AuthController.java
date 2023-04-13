package com.example.jwt.security.api.controller;

import com.example.jwt.domain.Member;
import com.example.jwt.mapper.MemberMapper;
import com.example.jwt.security.api.dto.request.LoginDto;
import com.example.jwt.security.api.dto.request.SignupDto;
import com.example.jwt.security.api.service.AuthService;
import com.example.jwt.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController("/api")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@Valid @RequestBody SignupDto signupDto) {
        Member member = MemberMapper.INSTANCE.toMember(signupDto);
        member.setPassword(passwordEncoder.encode(member.getPassword()));

        memberService.join(member);
        return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity login(@Valid @RequestBody LoginDto loginDto) {

    }
}
