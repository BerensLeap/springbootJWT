package com.springbootjwt.domain.user.enums;

import com.springbootjwt.common.exception.ApplicationException;
import com.springbootjwt.common.exception.ErrorCode;

import java.util.Arrays;

public enum Role {

    USER, ADMIN;

    public static Role of(String role) {
        return Arrays.stream(Role.values()).filter(r -> r.name().equalsIgnoreCase(role))
                .findFirst()
                .orElseThrow(()->new ApplicationException(ErrorCode.INVALID_USER_ROLE));
    }
}
