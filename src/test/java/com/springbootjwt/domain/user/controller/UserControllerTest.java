package com.springbootjwt.domain.user.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springbootjwt.common.exception.ApplicationException;
import com.springbootjwt.common.exception.ErrorCode;
import com.springbootjwt.common.jwt.JwtAuthenticationFilter;
import com.springbootjwt.domain.user.dto.request.LoginRequest;
import com.springbootjwt.domain.user.dto.request.SignupRequest;
import com.springbootjwt.domain.user.dto.response.LoginResponse;
import com.springbootjwt.domain.user.dto.response.SignupResponse;
import com.springbootjwt.domain.user.enums.Role;
import com.springbootjwt.domain.user.service.AuthService;
import com.springbootjwt.domain.user.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.doAnswer;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    void setup() throws Exception {
        doAnswer(invocation -> {
            HttpServletRequest request = invocation.getArgument(0);
            HttpServletResponse response = invocation.getArgument(1);
            FilterChain chain = invocation.getArgument(2);
            chain.doFilter(request, response);
            return null;
        }).when(jwtAuthenticationFilter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
    }

    // --- 회원가입 (Signup) 테스트 ---
    @Test
    @DisplayName("회원가입 성공 - 정상적인 사용자 정보")
    void signup_success() throws Exception {
        // Given
        SignupRequest request = new SignupRequest("testuser", "password123!", "tester", "USER");
        SignupResponse response = new SignupResponse("testuser", "tester", Role.USER);
        given(authService.signup(any(SignupRequest.class))).willReturn(response);

        // When & Then
        mockMvc.perform(post("/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk()) // 200 OK 예상
                .andExpect(jsonPath("$.userName").value("testuser"))
                .andExpect(jsonPath("$.nickName").value("tester"))
                .andExpect(jsonPath("$.role").value("USER"));

        verify(authService, times(1)).signup(any(SignupRequest.class)); // 서비스 메서드 호출 검증
    }

    @Test
    @DisplayName("회원가입 실패 - 이미 가입된 사용자 정보 (아이디 중복)")
    void signup_fail_userAlreadyExists() throws Exception {
        // Given
        SignupRequest request = new SignupRequest("existinguser", "password123!", "existing", "USER");
        // 서비스에서 예외를 던지도록 설정
        given(authService.signup(any(SignupRequest.class)))
                .willThrow(new ApplicationException(ErrorCode.USER_ALREADY_EXISTS));

        // When & Then
        mockMvc.perform(post("/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isConflict()) // 409 예상
                .andExpect(jsonPath("$.code").value("USER_ALREADY_EXISTS"));

        verify(authService, times(1)).signup(any(SignupRequest.class));
    }


    // --- 로그인 (Login) 테스트 ---
    @Test
    @DisplayName("로그인 성공 - 올바른 자격 증명")
    void login_success() throws Exception {
        // Given
        LoginRequest request = new LoginRequest("testuser", "password123!");
        LoginResponse response = new LoginResponse("accessTokenExample", "refreshTokenExample");
        given(authService.login(any(LoginRequest.class))).willReturn(response);

        // When & Then
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk()) // 200 OK 예상
                .andExpect(jsonPath("$.accessToken").value("accessTokenExample"))
                .andExpect(jsonPath("$.refreshToken").value("refreshTokenExample"));

        verify(authService, times(1)).login(any(LoginRequest.class));
    }

    @Test
    @DisplayName("로그인 실패 - 잘못된 자격 증명 (사용자 없음)")
    void login_fail_userNotFound() throws Exception {
        // Given
        LoginRequest request = new LoginRequest("nonexistent", "password123!");
        given(authService.login(any(LoginRequest.class)))
                .willThrow(new ApplicationException(ErrorCode.USER_NOT_FOUND));

        // When & Then
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound()) // 404 Not Found 예상
                .andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));

        verify(authService, times(1)).login(any(LoginRequest.class));
    }

    @Test
    @DisplayName("로그인 실패 - 잘못된 자격 증명 (비밀번호 불일치)")
    void login_fail_invalidCredentials() throws Exception {
        // Given
        LoginRequest request = new LoginRequest("testuser", "wrongpassword");
        given(authService.login(any(LoginRequest.class)))
                .willThrow(new ApplicationException(ErrorCode.INVALID_CREDENTIALS));

        // When & Then
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isUnauthorized()) // 401 Unauthorized 예상
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));

        verify(authService, times(1)).login(any(LoginRequest.class));
    }

    // --- 관리자 권한 부여 (Grant Admin Role) 테스트 ---
    @Test
    @DisplayName("관리자 권한 부여 성공 - ADMIN 권한을 가진 사용자 요청")
    void grantAdminRole_success_byAdminUser() throws Exception {
        // Given
        Long userId = 1L;
        SignupResponse response = new SignupResponse("targetUser", "targetNick", Role.ADMIN);
        given(authService.grantAdminRole(userId)).willReturn(response);

        // When & Then
        mockMvc.perform(patch("/admin/users/{userId}/roles", userId)
                        .with(csrf())
                        .with(user("adminUser").roles("ADMIN")))
                .andDo(print())
                .andExpect(status().isOk()) // 200 OK 예상
                .andExpect(jsonPath("$.userName").value("targetUser"))
                .andExpect(jsonPath("$.role").value("ADMIN"));

        verify(authService, times(1)).grantAdminRole(userId);
    }

    @Test
    @DisplayName("관리자 권한 부여 실패 - 일반 사용자가 요청 (403 Forbidden)")
    @WithMockUser(roles = "USER") // USER 권한 Mock 사용자 주입
    void grantAdminRole_fail_byNormalUser() throws Exception {
        // Given
        Long userId = 1L;

        // When & Then
        mockMvc.perform(patch("/admin/users/{userId}/roles", userId)
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isForbidden()); // 403 Forbidden 예상

        verify(authService, never()).grantAdminRole(anyLong()); // 서비스 메서드 호출 안 됨 확인
    }

    @Test
    @DisplayName("관리자 권한 부여 실패 - 인증되지 않은 사용자가 요청 (403 Forbidden)")
    void grantAdminRole_fail_unauthorizedUser() throws Exception {
        // Given
        Long userId = 1L;

        // When & Then
        mockMvc.perform(patch("/admin/users/{userId}/roles", userId)
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isForbidden()); // 403 Forbidden 예상

        verify(authService, never()).grantAdminRole(anyLong());
    }

    @Test
    @DisplayName("관리자 권한 부여 실패 - 존재하지 않는 사용자에게 권한 부여 시도")
    @WithMockUser(roles = "ADMIN") // ADMIN 권한 Mock 사용자 주입
    void grantAdminRole_fail_userNotFound() throws Exception {
        // Given
        Long userId = 99L; // 존재하지 않는 사용자 ID
        given(authService.grantAdminRole(userId))
                .willThrow(new ApplicationException(ErrorCode.USER_NOT_FOUND));

        // When & Then
        mockMvc.perform(patch("/admin/users/{userId}/roles", userId)
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound()) // 404 Not Found 예상
                .andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));

        verify(authService, times(1)).grantAdminRole(userId);
    }

    @Test
    @DisplayName("관리자 권한 부여 실패 - 이미 ADMIN 권한을 가진 사용자에게 부여 시도")
    @WithMockUser(roles = "ADMIN") // ADMIN 권한 Mock 사용자 주입
    void grantAdminRole_fail_alreadyAdminRole() throws Exception {
        // Given
        Long userId = 2L; // 이미 ADMIN인 사용자 ID 가정
        given(authService.grantAdminRole(userId))
                .willThrow(new ApplicationException(ErrorCode.ALREADY_ADMIN_ROLE));

        // When & Then
        mockMvc.perform(patch("/admin/users/{userId}/roles", userId)
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isConflict()) // 409 Conflict 예상
                .andExpect(jsonPath("$.code").value("ALREADY_ADMIN_ROLE"));

        verify(authService, times(1)).grantAdminRole(userId);
    }
}