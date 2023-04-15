package com.example.jwt.security.api.controller;

import com.example.jwt.domain.Member;
import com.example.jwt.mapper.MemberMapper;
import com.example.jwt.security.api.dto.request.LoginDto;
import com.example.jwt.security.api.dto.request.SignupDto;
import com.example.jwt.security.api.service.AuthService;
import com.example.jwt.security.jwt.TokenDto;
import com.example.jwt.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthService authService;
    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity signup(@Valid @RequestBody SignupDto signupDto) {
        Member member = MemberMapper.INSTANCE.toMember(signupDto);
        log.info("{}", member);
        member.setPassword(passwordEncoder.encode(member.getPassword()));
        member.setAdmin(false);

        ResponseEntity responseEntity = null;
        try {
            memberService.register(member);
            responseEntity = new ResponseEntity("registration success", HttpStatus.CREATED);

        } catch (Exception e) {
            responseEntity = new ResponseEntity("registration fail : " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        return responseEntity;
    }

    @PostMapping("/login")
    public ResponseEntity login(@Valid @RequestBody LoginDto loginDto) {
        TokenDto tokenDto = authService.login(loginDto);
        HttpCookie httpCookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken())
                .httpOnly(true)
                // https 에서만 데이터를 보내므로 잠시 주석처리
//                .secure(true)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenDto.getAccessToken())
                .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                .body("login success");
    }

    @GetMapping("/logout")
    public ResponseEntity logout(@RequestHeader("Authorization") String token) {
        authService.logout(token);
        ResponseCookie responseCookie = ResponseCookie.from("refreshToken", "")
                .maxAge(0)
                .path("/")
                .build();
        return ResponseEntity
                .status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .body("logout success");
    }

    @GetMapping("/mypage")
    public ResponseEntity mypage(@RequestHeader("Authorization") String token) {
        if (!authService.validateAccessToken(token) )  {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("invalid token");
        }
        Long memberId = authService.getMemberId(token);
        String memberInfo = memberService.getMemberInfo(memberId);
        return ResponseEntity.ok().body(memberInfo);
    }

    @GetMapping("/refresh")
    public ResponseEntity refresh(@CookieValue String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("refreshToken is null");
        }
        TokenDto tokenDto = null;
        try {
            tokenDto = authService.refreshToken(refreshToken);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }

        HttpCookie httpCookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken())
                .httpOnly(true)
//                .secure(true)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenDto.getAccessToken())
                .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                .body("refresh success");
    }
}
