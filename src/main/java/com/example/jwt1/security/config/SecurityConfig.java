package com.example.jwt1.security.config;

// 필요한 클래스들 import
import com.example.jwt1.security.jwt.JwtAuthenticationFilter;
import com.example.jwt1.security.jwt.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor // 생성자 자동 생성 (@Autowired 없이 의존성 주입 가능)
@Configuration // 이 클래스는 Spring 설정 파일임을 나타냄

public class SecurityConfig {
    private final JwtUtil jwtUtil; // JWT 유틸 클래스 주입 (필터에서 사용할 거임)

    /**
     * ✅ Spring Security의 필터 체인 설정
     * 이 메서드에서 어떤 요청을 허용하고, 어떤 필터를 적용할지 설정한다.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1️⃣ CSRF 보호 비활성화 (JWT는 세션을 쓰지 않기 때문에 필요 없음)
                .csrf(csrf -> csrf.disable())

                // 2️⃣ 세션을 사용하지 않음 (JWT는 상태를 서버에 저장하지 않음)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 3️⃣ 어떤 URL 요청을 허용할지 설정
                .authorizeHttpRequests(auth -> auth
                        //.requestMatchers("/api/auth/**").permitAll() // 기존 로그인/회원가입
                        .requestMatchers(
                                "/api/auth/**",
                                "/swagger-ui/**",        // Swagger UI 화면
                                "/v3/api-docs/**",       // Swagger API 문서
                                "/swagger-resources/**", // Swagger 리소스
                                "/webjars/**"            // Swagger 내부 리소스
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                /*.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // 회원가입, 로그인은 인증 없이 접근 허용
                        .anyRequest().authenticated() // 나머지 모든 요청은 인증 필요
                )*/

                // 4️⃣ 인증 실패 시 401 에러 응답 설정
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증되지 않은 요청입니다.");
                        })
                )

                // 5️⃣ 우리가 만든 JWT 필터를 UsernamePasswordAuthenticationFilter 앞에 등록
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 6️⃣ 위에서 설정한 필터 체인을 Bean으로 등록
        return http.build();
    }

    /**
     * ✅ AuthenticationManager Bean 등록
     * 로그인 처리 시 사용할 인증 관리자
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager(); // 자동으로 구성된 AuthenticationManager 반환
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
