package com.security.jwtAndOauth.domain;

import lombok.Data;

@Data
public class MemberDto {
    private String email;
    private String password;
    private String role;
}
