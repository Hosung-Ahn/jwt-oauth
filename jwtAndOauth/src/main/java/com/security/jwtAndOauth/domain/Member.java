package com.security.jwtAndOauth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter @Setter
public class Member {
    @Id @GeneratedValue
    @Column(name = "user_id")
    private Long id;

    private String nickname;

    @Column(unique = true)
    private String email;

    private String password;

    private String role;
}
