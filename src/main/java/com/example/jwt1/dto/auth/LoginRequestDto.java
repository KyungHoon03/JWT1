package com.example.jwt1.dto.auth;
import lombok.Getter;

@Getter
public class LoginRequestDto {
    private String username;
    private String password;
}
