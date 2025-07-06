package com.example.jwt1.domain.auth.service;

import com.example.jwt1.domain.user.entity.User;
import com.example.jwt1.domain.user.repository.UserRepository;
import com.example.jwt1.security.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service // 서비스 계층임을 명시
@RequiredArgsConstructor // 생성자 자동 주입
public class AuthService {
    private final UserRepository userRepository; // 사용자 저장/조회
    private final PasswordEncoder passwordEncoder; // 비밀번호 암호화
    private final JwtUtil jwtUtil; // JWT 생성/검증 유틸

    // ✅ 회원가입
    public void signup(String username, String password) {
        // 이미 존재하는 사용자면 예외
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("이미 존재하는 사용자입니다.");
        }

        // 비밀번호 암호화해서 저장
        String encodedPassword = passwordEncoder.encode(password);
        User user = new User(username, encodedPassword, "ROLE_USER");

        userRepository.save(user);
    }
    // ✅ 로그인 → JWT 발급
    public String login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // JWT 토큰 생성
        return jwtUtil.createToken(user.getUsername(), user.getRole());
    }

}
