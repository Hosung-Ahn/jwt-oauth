package com.security.jwtAndOauth.controller;

import com.security.jwtAndOauth.domain.Member;
import com.security.jwtAndOauth.domain.MemberDto;
import com.security.jwtAndOauth.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final MemberService memberService;

    @PostMapping("/api/register")
    public ResponseEntity<String> register(@Valid @RequestBody MemberDto memberDto) {
        Member member = new Member();
        member.setEmail(memberDto.getEmail());
        member.setPassword(memberDto.getPassword());
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
}
