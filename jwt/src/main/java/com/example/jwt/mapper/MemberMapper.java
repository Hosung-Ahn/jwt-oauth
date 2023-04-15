package com.example.jwt.mapper;

import com.example.jwt.domain.Member;
import com.example.jwt.security.dto.request.SignupDto;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;
import org.mapstruct.factory.Mappers;

@Mapper
public interface MemberMapper {

    @Mappings({
            @Mapping(target = "nickname", expression = "java(signUpDto.getEmail().substring(0, signUpDto.getEmail().indexOf('@')))")
    })
    Member toMember(SignupDto signUpDto);
    MemberMapper INSTANCE = Mappers.getMapper(MemberMapper.class);
}
