package com.example.jwt.mapper;

import com.example.jwt.domain.Member;
import com.example.jwt.security.dto.request.SignupDto;
import javax.annotation.processing.Generated;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2023-04-16T01:30:17+0900",
    comments = "version: 1.5.3.Final, compiler: javac, environment: Java 17.0.6 (Oracle Corporation)"
)
public class MemberMapperImpl implements MemberMapper {

    @Override
    public Member toMember(SignupDto signUpDto) {
        if ( signUpDto == null ) {
            return null;
        }

        Member member = new Member();

        member.setNickname( signUpDto.getEmail().substring(0, signUpDto.getEmail().indexOf('@')) );

        return member;
    }
}
