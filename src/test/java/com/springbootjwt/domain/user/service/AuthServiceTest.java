package com.springbootjwt.domain.user.service;

import com.springbootjwt.common.exception.ApplicationException;
import com.springbootjwt.common.exception.ErrorCode;
import com.springbootjwt.common.jwt.JwtUtil;
import com.springbootjwt.common.service.RedisService;
import com.springbootjwt.domain.user.dto.request.LoginRequest;
import com.springbootjwt.domain.user.dto.request.SignupRequest;
import com.springbootjwt.domain.user.dto.response.LoginResponse;
import com.springbootjwt.domain.user.dto.response.SignupResponse;
import com.springbootjwt.domain.user.entity.User;
import com.springbootjwt.domain.user.enums.Role;
import com.springbootjwt.domain.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private RedisService redisService;

    private User testUser;
    private SignupRequest signupRequest;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1L)
                .userName("testuser")
                .password("password123!")
                .nickName("tester")
                .role(Role.USER)
                .build();

        signupRequest = new SignupRequest("newuser", "newpass123!", "newnick", "USER");
        loginRequest = new LoginRequest("testuser", "password123!");
    }

    // --- 회원가입 (signup) 테스트 ---
    @Test
    @DisplayName("회원가입 성공")
    void signup_success() {
        // Given
        given(userRepository.existsByUserName(signupRequest.getUserName())).willReturn(false); // 사용자 없음
        given(passwordEncoder.encode(signupRequest.getPassword())).willReturn("encodedNewPass"); // 비밀번호 암호화
        given(userRepository.save(any(User.class))).willAnswer(returnsFirstArg());

        // When
        SignupResponse response = authService.signup(signupRequest);

        // Then
        assertThat(response.getUserName()).isEqualTo(signupRequest.getUserName());
        assertThat(response.getNickName()).isEqualTo(signupRequest.getNickName());
        assertThat(response.getRole()).isEqualTo(Role.of(signupRequest.getRole()));

        verify(userRepository, times(1)).existsByUserName(signupRequest.getUserName());
        verify(passwordEncoder, times(1)).encode(signupRequest.getPassword());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("회원가입 실패 - 아이디 중복")
    void signup_fail_userAlreadyExists() {
        // Given
        given(userRepository.existsByUserName(signupRequest.getUserName())).willReturn(true); // 사용자 이미 존재

        // When & Then
        ApplicationException exception = assertThrows(ApplicationException.class,
                () -> authService.signup(signupRequest));

        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.USER_ALREADY_EXISTS);
        verify(userRepository, times(1)).existsByUserName(signupRequest.getUserName());
        verify(passwordEncoder, never()).encode(anyString()); // 암호화 메서드 호출 안 됨 확인
        verify(userRepository, never()).save(any(User.class)); // 저장 메서드 호출 안 됨 확인
    }

    // --- 로그인 (login) 테스트 ---
    @Test
    @DisplayName("로그인 성공")
    void login_success() {
        // Given
        given(userRepository.findByUserName(loginRequest.getUserName())).willReturn(Optional.of(testUser));
        given(passwordEncoder.matches(loginRequest.getPassword(), testUser.getPassword())).willReturn(true);
        given(jwtUtil.createAccessToken(anyLong(), anyString(), any(Role.class))).willReturn("testAccessToken");
        given(jwtUtil.createRefreshToken(anyLong(), anyString(), any(Role.class))).willReturn("testRefreshToken");

        // When
        LoginResponse response = authService.login(loginRequest);

        // Then
        assertThat(response.getAccessToken()).isEqualTo("testAccessToken");
        assertThat(response.getRefreshToken()).isEqualTo("testRefreshToken");

        verify(userRepository, times(1)).findByUserName(loginRequest.getUserName());
        verify(passwordEncoder, times(1)).matches(loginRequest.getPassword(), testUser.getPassword());
        verify(jwtUtil, times(1)).createAccessToken(anyLong(), anyString(), any(Role.class));
        verify(jwtUtil, times(1)).createRefreshToken(anyLong(), anyString(), any(Role.class));
    }

    @Test
    @DisplayName("로그인 실패 - 사용자 없음")
    void login_fail_userNotFound() {
        // Given
        given(userRepository.findByUserName(loginRequest.getUserName())).willReturn(Optional.empty());

        // When & Then
        ApplicationException exception = assertThrows(ApplicationException.class,
                () -> authService.login(loginRequest));

        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_FOUND);
        verify(userRepository, times(1)).findByUserName(loginRequest.getUserName());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("로그인 실패 - 비밀번호 불일치")
    void login_fail_invalidCredentials() {
        // Given
        given(userRepository.findByUserName(loginRequest.getUserName())).willReturn(Optional.of(testUser));
        given(passwordEncoder.matches(loginRequest.getPassword(), testUser.getPassword())).willReturn(false);

        // When & Then
        ApplicationException exception = assertThrows(ApplicationException.class,
                () -> authService.login(loginRequest));

        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        verify(userRepository, times(1)).findByUserName(loginRequest.getUserName());
        verify(passwordEncoder, times(1)).matches(loginRequest.getPassword(), testUser.getPassword());
    }

    // --- 관리자 권한 부여 (grantAdminRole) 테스트 ---
    @Test
    @DisplayName("ADMIN 권한 부여 성공")
    void grantAdminRole_success() {
        // Given
        User userToGrantAdmin = User.builder()
                .id(2L)
                .userName("userToAdmin")
                .password("encodedpass")
                .nickName("ordinaryUser")
                .role(Role.USER) // USER 권한으로 시작
                .build();
        given(userRepository.findById(2L)).willReturn(Optional.of(userToGrantAdmin));
        given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0)); // save 호출 시 그대로 반환

        // When
        SignupResponse response = authService.grantAdminRole(2L);

        // Then
        assertThat(response.getUserName()).isEqualTo("userToAdmin");
        assertThat(response.getRole()).isEqualTo(Role.ADMIN); // ADMIN으로 변경 확인
        verify(userRepository, times(1)).findById(2L);
        verify(userRepository, times(1)).save(userToGrantAdmin); // save 호출 확인
        assertThat(userToGrantAdmin.getRole()).isEqualTo(Role.ADMIN); // 실제 엔티티의 역할 변경 확인
    }

    @Test
    @DisplayName("ADMIN 권한 부여 실패 - 사용자 없음")
    void grantAdminRole_fail_userNotFound() {
        // Given
        given(userRepository.findById(anyLong())).willReturn(Optional.empty()); // 사용자 없음

        // When & Then
        ApplicationException exception = assertThrows(ApplicationException.class,
                () -> authService.grantAdminRole(99L));

        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_FOUND);
        verify(userRepository, times(1)).findById(99L);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("ADMIN 권한 부여 실패 - 이미 ADMIN 권한을 가진 사용자")
    void grantAdminRole_fail_alreadyAdmin() {
        // Given
        User adminUser = User.builder()
                .id(3L)
                .userName("existingAdmin")
                .password("encodedpass")
                .nickName("admin")
                .role(Role.ADMIN) // 이미 ADMIN 권한
                .build();
        given(userRepository.findById(3L)).willReturn(Optional.of(adminUser));

        // When & Then
        ApplicationException exception = assertThrows(ApplicationException.class,
                () -> authService.grantAdminRole(3L));

        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.ALREADY_ADMIN_ROLE);
        verify(userRepository, times(1)).findById(3L);
        verify(userRepository, never()).save(any(User.class)); // save 호출 안 됨 확인
    }
}