package com.example.jwt.service;

import com.example.jwt.domain.Member;
import com.example.jwt.repository.AuthorityRepository;
import com.example.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {
    private final MemberRepository memberRepository;
    private final AuthorityRepository authorityRepository;

    @Transactional
    public Long register(Member member) {
        validateDuplicateMember(member);
        if (member.isAdmin()) member.getAuthorities().add(authorityRepository.findByName("ROLE_ADMIN"));
        else member.getAuthorities().add(authorityRepository.findByName("ROLE_USER"));
        memberRepository.save(member);
        return member.getId();
    }

    private void validateDuplicateMember(Member member) {
        memberRepository.findByEmail(member.getEmail())
                .ifPresent(m -> {
                    throw new IllegalStateException("이미 존재하는 회원입니다.");
                });
    }
}
