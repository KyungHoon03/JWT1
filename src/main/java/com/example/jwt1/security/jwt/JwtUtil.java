package com.example.jwt1.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;


@Component // 스프링에서 이 클래스를 Bean으로 등록해서 의존성 주입이 가능하게 해줌

public class JwtUtil {
    // === 🔐 JWT 설정값 ===

    // 비밀 키 (서명할 때 사용, 256비트 이상 길이 권장)
    private static final String SECRET_KEY = "secret.secret.secret.secret.secret";

    // 토큰 유효 시간 (1000ms * 60초 * 60분 * 2시간 = 2시간)
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 2;

    // 위에서 설정한 비밀키를 이용해서 서명용 Key 객체 생성
    private final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    /**
     * ✅ JWT 토큰을 생성하는 메서드
     * @param username 사용자 이름 또는 ID
     * @param role 사용자 역할 (ex. ROLE_USER, ROLE_ADMIN)
     * @return JWT 토큰 문자열
     */
    public String createToken(String username, String role) {
        return Jwts.builder() // JWT 토큰을 만들기 시작
                .setSubject(username) // 토큰 주제(subject)로 사용자 이름 설정
                .claim("role", role) // 사용자 역할을 claim(추가 정보)으로 담음
                .setIssuedAt(new Date()) // 토큰 발급 시간 설정
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // 만료 시간 설정
                .signWith(key, SignatureAlgorithm.HS256) // 비밀키와 서명 알고리즘 설정
                .compact(); // 최종적으로 토큰 문자열 생성
    }

    /**
     * ✅ 토큰에서 사용자 이름(Subject)을 추출
     */
    public String getUsername(String token) {
        return parseClaims(token).getBody().getSubject(); // 토큰에서 subject 가져오기
    }
    /**
     * ✅ 토큰에서 사용자 Role(권한)을 추출
     */
    public String getUserRole(String token) {
        return parseClaims(token).getBody().get("role", String.class); // 토큰의 role claim 꺼내기
    }
    /**
     * ✅ 토큰의 유효성을 검사 (만료 여부, 서명 오류 등)
     */
    public boolean validateToken(String token) {
        try {
            parseClaims(token); // 문제가 없으면 true
            return true;
        } catch (ExpiredJwtException e) { // 유효시간 만료
            System.out.println("만료된 토큰입니다.");
        } catch (JwtException e) { // 토큰 오류
            System.out.println("잘못된 토큰입니다.");
        }
        return false; // 예외 발생 시 false 반환
    }
    /**
     * ✅ 토큰을 파싱하고 서명을 검증해서 Claims(정보)를 반환
     * @param token JWT 토큰
     * @return 파싱된 토큰의 Claims
     */
    private Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder() // JWT 파서 생성
                .setSigningKey(key) // 서명 검증을 위한 키 설정
                .build() // 파서 완성
                .parseClaimsJws(token); // 토큰을 파싱하고 서명 검증까지 수행
    }
}
