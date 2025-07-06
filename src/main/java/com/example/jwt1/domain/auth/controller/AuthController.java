package com.example.jwt1.domain.auth.controller;


import com.example.jwt1.domain.auth.service.AuthService;
import com.example.jwt1.dto.auth.LoginRequestDto;
import com.example.jwt1.dto.auth.SignupRequestDto;
import com.example.jwt1.dto.auth.TokenResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController // REST API 컨트롤러
@RequestMapping("/api/auth") // 공통 URL prefix
@RequiredArgsConstructor // 생성자 자동 주입
public class AuthController {

    private final AuthService authService;

    // ✅ 회원가입 API: POST /api/auth/signup
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequestDto requestDto) {
        authService.signup(requestDto.getUsername(), requestDto.getPassword());
        return ResponseEntity.ok("회원가입 성공");
    }

    // ✅ 로그인 API: POST /api/auth/login
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(@RequestBody LoginRequestDto requestDto) {
        String token = authService.login(requestDto.getUsername(), requestDto.getPassword());
        return ResponseEntity.ok(new TokenResponseDto(token));
    }
}
