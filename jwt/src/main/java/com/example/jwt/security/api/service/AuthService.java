package com.example.jwt.security.api.service;

import com.example.jwt.security.jwt.JwtTokenProvider;
import com.example.jwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberService memberService;
    private final JwtTokenProvider jwtTokenProvider;


    
}
