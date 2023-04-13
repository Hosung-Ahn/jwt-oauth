package com.example.jwt.service;

import com.example.jwt.domain.Member;
import com.example.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;

    public Long join(Member member) {
        validateDuplicateMember(member);
        memberRepository.save(member);
        return member.getId();
    }

    private void validateDuplicateMember(Member member) {
        if (memberRepository.existsByEmail(member.getEmail())) {
            throw new IllegalStateException("이미 존재하는 회원입니다.");
        }
    }
}
