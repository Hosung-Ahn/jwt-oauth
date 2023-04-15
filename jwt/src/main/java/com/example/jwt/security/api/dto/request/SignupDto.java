package com.example.jwt.security.api.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignupDto {
    private String email;
    private String password;
    private String nickname;
}
