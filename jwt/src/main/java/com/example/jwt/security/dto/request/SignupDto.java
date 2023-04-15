package com.example.jwt.security.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
public class SignupDto {
    private String email;
    private String password;
    private String nickname;
}
