package com.example.jwt1.domain.user.entity;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
@Table(name = "users")
public class User {
    @Id // 이 필드는 기본 키(Primary Key)임을 나타냄
    @GeneratedValue(strategy = GenerationType.IDENTITY) // auto_increment처럼 자동 증가 설정
    private Long id; // 사용자 고유 ID (DB에서 자동 생성됨)

    @Column(nullable = false, unique = true) // null 불가 + 유일한 값
    private String username; // 사용자 이름 (로그인 ID로 사용됨)

    @Column(nullable = false) // null 불가
    private String password; // 비밀번호 (암호화해서 저장할 예정)

    @Column(nullable = false) // null 불가
    private String role; // 사용자 권한 (예: ROLE_USER, ROLE_ADMIN)

    public User(Long id, String username, String password, String role) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = role;
    }
    public User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }
    public User() {
    }
}
