package com.security.jwtAndOauth.domain;

import lombok.Data;

@Data
public class MemberDto {

    private String nickname;
    private String email;
    private String password;
    private String role;
}
