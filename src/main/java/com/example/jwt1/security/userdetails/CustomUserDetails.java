package com.example.jwt1.security.userdetails;

import com.example.jwt1.domain.user.entity.User;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Getter // Lombok으로 getter 자동 생성
public class CustomUserDetails implements UserDetails {

    private final User user; // 우리가 만든 User 엔티티를 포함

    public CustomUserDetails(User user) {
        this.user = user;

    }
    // 사용자 권한을 반환 (지금은 단일 role만 처리)
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList(); // 지금은 권한 없음 처리 (나중에 넣을 수 있음)
    }

    // 사용자 비밀번호 반환
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    // 사용자 이름(username) 반환
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정 만료 여부 (true = 만료되지 않음)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정 잠김 여부
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 자격 증명(비밀번호) 만료 여부
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 활성화 여부
    @Override
    public boolean isEnabled() {
        return true;
    }

}
