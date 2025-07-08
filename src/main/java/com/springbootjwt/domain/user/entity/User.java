package com.springbootjwt.domain.user.entity;

import com.springbootjwt.domain.user.enums.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String userName;
    private String password;
    private String nickName;

    @Enumerated(EnumType.STRING)
    private Role role;

    public User(String userName, String password, String nickName, Role role) {
        this.userName = userName;
        this.password = password;
        this.nickName = nickName;
        this.role = role;
    }

    public void updateRole(Role newRole) {
        this.role = newRole;
    }
}
