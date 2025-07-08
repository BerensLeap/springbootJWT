package com.springbootjwt.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

@Getter
public enum ErrorCode {

    EXCEPTION(INTERNAL_SERVER_ERROR,"EXCEPTION", "알 수 없는 에러입니다."),
    USER_ALREADY_EXISTS(CONFLICT, "USER_ALREADY_EXISTS", "이미 가입된 사용자입니다."),
    INVALID_CREDENTIALS(UNAUTHORIZED, "INVALID_CREDENTIALS", "아이디 또는 비밀번호가 올바르지 않습니다."),
    ACCESS_DENIED(FORBIDDEN, "ACCESS_DENIED", "접근 권한이 없습니다."),
    INVALID_TOKEN(UNAUTHORIZED, "INVALID_TOKEN", "유효하지 않은 인증 토큰입니다."),
    EXPIRED_TOKEN(UNAUTHORIZED, "EXPIRED_TOKEN", "만료된 인증 토큰입니다."),
    REFRESH_TOKEN_FORBIDDEN(FORBIDDEN,"REFRESH_TOKEN_FORBIDDEN","Refresh Token으로 접근할 수 없습니다."),
    UNSUPPORTED_TOKEN(BAD_REQUEST, "UNSUPPORTED_TOKEN","지원되지 않는 JWT 토큰입니다."),
    USER_NOT_FOUND(NOT_FOUND, "USER_NOT_FOUND", "존재하지 않는 계정입니다."),
    INVALID_USER_ROLE(FORBIDDEN,"INVALID_USER_ROLE","유효하지 않은 권한 입니다."),
    ALREADY_ADMIN_ROLE(BAD_REQUEST,"ALREADY_ADMIN_ROLE","이미 ADMIN권한을 보유한 사용자입니다.")
    ;

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;

    ErrorCode(HttpStatus httpStatus, String code, String message) {
        this.httpStatus = httpStatus;
        this.code = code;
        this.message = message;
    }
}
