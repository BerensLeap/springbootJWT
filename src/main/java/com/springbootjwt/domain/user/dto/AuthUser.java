package com.springbootjwt.domain.user.dto;

import com.springbootjwt.domain.user.enums.Role;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

@Getter
public class AuthUser {

    private final Long id;
    private final String userName;
    private final Collection<? extends GrantedAuthority> authorities;

    public AuthUser(Long id, String userName, Role role) {
        this.id = id;
        this.userName = userName;
        this.authorities = List.of(new SimpleGrantedAuthority(role.name()));
    }
}
