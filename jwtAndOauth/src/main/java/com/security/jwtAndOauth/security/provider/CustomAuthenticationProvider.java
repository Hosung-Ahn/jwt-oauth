package com.security.jwtAndOauth.security.provider;

import com.security.jwtAndOauth.domain.Member;
import com.security.jwtAndOauth.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;



    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        if (! memberRepository.existsByEmail(username)) {
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다.");
        }
        Member member = memberRepository.findByEmail(username);
        List<GrantedAuthority> authorities = List.of(() -> member.getRole());

        if (! passwordEncoder.matches(password, member.getPassword())) {
            throw new UsernameNotFoundException("비밀번호가 일치하지 않습니다.");
        }
        return new UsernamePasswordAuthenticationToken(member, password, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
