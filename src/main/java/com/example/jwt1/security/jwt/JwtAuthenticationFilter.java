package com.example.jwt1.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;
/**
 * ✅ 이 필터는 매 요청마다 작동하며, 요청에 담긴 JWT 토큰을 검사하고
 * 유효하면 Spring Security가 인식할 수 있도록 인증 객체를 등록해준다.
 */
//OncePerRequestFilter
// "하나의 요청마다 단 한 번만 실행되는 필터"를 만들기 위한 Spring 제공 클래스입니다.

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    // 생성자에서 JwtUtil 주입받기
    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }
    /**
     * ✅ 매 요청마다 실행되는 필터의 핵심 로직
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // 1️⃣ 요청 헤더에서 "Authorization" 값을 꺼냄
        String authHeader = request.getHeader("Authorization");

        // 2️⃣ Authorization 헤더가 없거나 "Bearer "로 시작하지 않으면 인증하지 않고 다음 필터로 넘김
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // 필터 체인 계속 진행
            return;
        }

        // 3️⃣ "Bearer " 다음에 오는 진짜 토큰 문자열만 추출 (앞 7글자 자르고 나머지를 가져옴)
        String token = authHeader.substring(7);

        // 4️⃣ 토큰이 유효하지 않으면 인증하지 않고 다음 필터로 넘김
        if (!jwtUtil.validateToken(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 5️⃣ 토큰에서 사용자 이름과 역할을 꺼냄
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getUserRole(token);

        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        // 6️⃣ 스프링 시큐리티가 이해할 수 있는 인증 객체를 생성함
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        // 사용자 정보 (User 객체로 생성, 비밀번호는 빈 문자열로 처리)
                        new User(username, "", authorities),
                        null, // 자격 증명 (보통 비밀번호인데 여기선 사용하지 않음)
                        authorities // 권한 리스트 (나중에 필요하면 넣기)
                );

        // 7️⃣ 인증 객체에 요청 정보를 추가 (IP, 세션 정보 등)
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        // 8️⃣ 시큐리티 컨텍스트에 인증 객체 등록 → 이후 컨트롤러에서 @AuthenticationPrincipal 등 사용 가능
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 9️⃣ 다음 필터로 요청 넘기기
        filterChain.doFilter(request, response);
    }

}
