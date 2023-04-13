package com.example.jwt.mapper;

import com.example.jwt.domain.Member;
import com.example.jwt.security.api.dto.request.SignupDto;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface MemberMapper {

    MemberMapper INSTANCE = Mappers.getMapper(MemberMapper.class);

    // SignUpDto to Member Entity
    Member toMember(SignupDto signUpDto);
}
