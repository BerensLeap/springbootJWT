package com.springbootjwt.domain.user.dto.response;

import com.springbootjwt.domain.user.entity.User;
import com.springbootjwt.domain.user.enums.Role;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserResponse {

    private final Long id;
    private final String userName;
    private final String nickName;
    private final Role role;

    public static UserResponse fromEntity(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .userName(user.getUserName())
                .nickName(user.getNickName())
                .role(user.getRole())
                .build();
    }
}
