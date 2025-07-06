package com.example.jwt1.security.userdetails;

import com.example.jwt1.domain.user.entity.User;
import com.example.jwt1.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.UserDetailsService;

@Service // 스프링이 이 클래스를 자동으로 Bean으로 등록하도록 함
@RequiredArgsConstructor // 생성자 주입 자동 처리
public class CustomUserDetailsService implements UserDetailsService{
    private final UserRepository userRepository; // DB에서 사용자 조회를 위해 주입
    /**
     * ✅ 사용자 이름(username)으로 사용자 정보를 DB에서 조회하고,
     * Spring Security가 이해할 수 있는 UserDetails 객체로 변환해서 반환한다.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // DB에서  username으로 사용자 찾고, 없으면 예외 발생
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));

        // CustomUserDetails로 감싸서 반환 (스프링 시큐리티가 사용함)
        return new CustomUserDetails(user);
    }
}
