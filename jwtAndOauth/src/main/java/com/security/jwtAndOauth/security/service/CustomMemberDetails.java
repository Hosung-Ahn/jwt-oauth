package com.security.jwtAndOauth.security.service;

import com.security.jwtAndOauth.domain.Member;
import com.security.jwtAndOauth.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomMemberDetails implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String email, password = null;
        List<GrantedAuthority> authorities = null;


        if (! memberRepository.existsByEmail(username)) {
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다. : " + username);
        }

        Member member = memberRepository.findByEmail(username);
        email = member.getEmail();
        password = member.getPassword();
        authorities = List.of(() -> member.getRole());

        return new User(email, password, authorities);
    }
}
