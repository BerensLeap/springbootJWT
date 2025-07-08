package com.springbootjwt.domain.user.controller;

import com.springbootjwt.domain.user.dto.request.LoginRequest;
import com.springbootjwt.domain.user.dto.request.SignupRequest;
import com.springbootjwt.domain.user.dto.response.LoginResponse;
import com.springbootjwt.domain.user.dto.response.SignupResponse;
import com.springbootjwt.domain.user.service.AuthService;
import com.springbootjwt.domain.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "User API", description = "회원가입, 로그인, 권한 부여 API")
@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final AuthService authService;

    @PostMapping("/signup")
    @Operation(summary = "회원가입")
    public ResponseEntity<SignupResponse> signup(@RequestBody SignupRequest signupRequest) {
        return ResponseEntity.ok().body(authService.signup(signupRequest));
    }

    @PostMapping("/login")
    @Operation(summary = "로그인")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok().body(authService.login(loginRequest));
    }

    @PatchMapping("/admin/users/{userId}/roles")
    @Operation(summary = "'USER'권한을 가진 특정 사용자에게 'ADMIN'권한을 부여")
    public ResponseEntity<SignupResponse> grantAdminRole(
            @Parameter(description = "'ADMIN'권한을 부여할 사용자ID")
            @PathVariable Long userId) {
        return ResponseEntity.ok().body(authService.grantAdminRole(userId));
    }
}
