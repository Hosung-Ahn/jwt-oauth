package com.example.jwt.mapper;

import com.example.jwt.domain.Member;
import com.example.jwt.security.api.dto.request.SignupDto;
import javax.annotation.processing.Generated;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2023-04-14T15:30:50+0900",
    comments = "version: 1.5.3.Final, compiler: javac, environment: Java 17.0.6 (Oracle Corporation)"
)
public class MemberMapperImpl implements MemberMapper {

    @Override
    public Member toMember(SignupDto signUpDto) {
        if ( signUpDto == null ) {
            return null;
        }

        Member member = new Member();

        member.setEmail( signUpDto.getEmail() );
        member.setPassword( signUpDto.getPassword() );

        member.setNickname( signUpDto.getEmail().substring(0, signUpDto.getEmail().indexOf('@')) );

        return member;
    }
}
