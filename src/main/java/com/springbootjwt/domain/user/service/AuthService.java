package com.springbootjwt.domain.user.service;

import com.springbootjwt.common.jwt.JwtUtil;
import com.springbootjwt.common.exception.ApplicationException;
import com.springbootjwt.common.exception.ErrorCode;
import com.springbootjwt.common.service.RedisService;
import com.springbootjwt.domain.user.dto.request.LoginRequest;
import com.springbootjwt.domain.user.dto.request.SignupRequest;
import com.springbootjwt.domain.user.dto.response.LoginResponse;
import com.springbootjwt.domain.user.dto.response.SignupResponse;
import com.springbootjwt.domain.user.entity.User;
import com.springbootjwt.domain.user.enums.Role;
import com.springbootjwt.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtUtil jwtUtil;

    private final RedisService redisService;

    @Transactional
    public SignupResponse signup(SignupRequest signupRequest) {
        String userName = signupRequest.getUserName();

        if (userRepository.existsByUserName(userName)) {
            throw new ApplicationException(ErrorCode.USER_ALREADY_EXISTS);
        }

        String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());

        User user = new User(
                signupRequest.getUserName(),
                encodedPassword,
                signupRequest.getNickName(),
                Role.of(signupRequest.getRole())
        );

        userRepository.save(user);

        return new SignupResponse(user);
    }

    @Transactional
    public LoginResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByUserName(loginRequest.getUserName())
                .orElseThrow(() -> new ApplicationException(ErrorCode.USER_NOT_FOUND));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new ApplicationException(ErrorCode.INVALID_CREDENTIALS);
        }
        String accessToken = jwtUtil.createAccessToken(user.getId(), user.getUserName(), user.getRole());
        String refreshToken = jwtUtil.createRefreshToken(user.getId(), user.getUserName(), user.getRole());

        return new LoginResponse(accessToken, refreshToken);
    }

    @Transactional
    public LoginResponse refreshToken(String refreshToken) {
        Long userId = Long.valueOf(jwtUtil.extractClaims(refreshToken).getSubject());

        jwtUtil.validateToken(refreshToken, String.valueOf(userId));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApplicationException(ErrorCode.USER_NOT_FOUND));

        String newAccessToken = jwtUtil.createAccessToken(user.getId(), user.getUserName(), user.getRole());

        return new LoginResponse(newAccessToken, refreshToken);
    }

    @Transactional
    public SignupResponse grantAdminRole(Long userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ApplicationException(ErrorCode.USER_NOT_FOUND));

        if (user.getRole() == Role.ADMIN) {
            throw new ApplicationException(ErrorCode.ALREADY_ADMIN_ROLE);
        }

        user.updateRole(Role.ADMIN);
        userRepository.save(user);
        return new SignupResponse(user);
    }
}
