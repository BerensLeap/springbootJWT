package com.springbootjwt.domain.user.service;

import com.springbootjwt.common.exception.ApplicationException;
import com.springbootjwt.common.exception.ErrorCode;
import com.springbootjwt.domain.user.dto.response.UserResponse;
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

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @InjectMocks
    private UserService userService;

    @Mock
    private UserRepository userRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1L)
                .userName("testuser")
                .password("password")
                .nickName("tester")
                .role(Role.USER)
                .build();
    }

    @Test
    @DisplayName("사용자 ID로 조회 성공")
    void findById_success() {
        // Given: userRepository.findById(testUser.getId())가 testUser를 Optional로 반환
        given(userRepository.findById(testUser.getId())).willReturn(Optional.of(testUser));

        // When: userService.findById 메서드 호출
        UserResponse response = userService.findById(testUser.getId());

        // Then: 반환된 UserResponse가 예상과 일치하는지 검증
        assertThat(response).isNotNull(); // 응답이 null이 아닌지 확인
        assertThat(response.getId()).isEqualTo(testUser.getId()); // ID 일치 확인
        assertThat(response.getUserName()).isEqualTo(testUser.getUserName()); // userName 일치 확인
        assertThat(response.getNickName()).isEqualTo(testUser.getNickName()); // nickName 일치 확인
        assertThat(response.getRole()).isEqualTo(testUser.getRole()); // Role 일치 확인

        // userRepository.findById가 정확히 한 번 호출되었는지 검증
        verify(userRepository, times(1)).findById(testUser.getId());
    }

    @Test
    @DisplayName("사용자 ID로 조회 실패 - 사용자 없음")
    void findById_fail_userNotFound() {
        // Given: userRepository.findById가 Optional를 반환하도록 설정
        given(userRepository.findById(anyLong())).willReturn(Optional.empty());

        // When & Then: userService.findById 호출 시 ApplicationException이 발생,
        // 해당 예외의 에러 코드가 USER_NOT_FOUND인지 검증
        ApplicationException exception = assertThrows(ApplicationException.class,
                () -> userService.findById(99L)); // 존재하지 않는 ID로 조회 시도

        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_FOUND); // 에러 코드 일치 확인

        // userRepository.findById가 정확히 한 번 호출되었는지 검증
        verify(userRepository, times(1)).findById(99L);
    }
}