package com.springbootjwt.domain.user.dto.response;

import com.springbootjwt.domain.user.entity.User;
import com.springbootjwt.domain.user.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class SignupResponse {
    private String userName;
    private String nickName;
    private Role role;

    public SignupResponse(User user) {
        this.userName = user.getUserName();
        this.nickName = user.getNickName();
        this.role = user.getRole();
    }
}
