package com.springbootjwt.common.jwt;

import com.springbootjwt.common.exception.ApplicationException;
import com.springbootjwt.common.exception.ErrorCode;
import com.springbootjwt.common.service.RedisService;
import com.springbootjwt.domain.user.enums.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final RedisService redisService;
    private static final String BEARER_PREFIX = "Bearer ";
    private static final Long ACCESS_TOKEN_TIME = 60 * 30 * 1000L; // 30분
    private static final Long REFRESH_TOKEN_TIME = 60 * 60 * 1000L * 24; // 1일

    @Value("${jwt.secret.key}")
    private String secretKey;
    private SecretKey key;

    @PostConstruct
    public void init() {
        log.info(">>> Loaded secret key: {}", secretKey);
        key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(Long userId,String userName, Role role, Long validTime, String tokenType) {
        Date date = new Date();
        log.info("JWT 생성 - userId: {},이름: {}, 역할: {}, 토큰 타입: {}", userId, userName, role.name(), tokenType); //

        return BEARER_PREFIX +
                Jwts.builder()
                        .subject(String.valueOf(userId))
                        .claim("이름", userName)
                        .claim("role", role.name())
                        .claim("tokenType", tokenType)
                        .expiration(new Date(date.getTime() + validTime))
                        .issuedAt(date)
                        .signWith(key)
                        .compact();
    }

    public String createAccessToken(Long userId, String userName, Role role) {
        String accessToken = this.createToken(userId, userName, role, ACCESS_TOKEN_TIME, "access");
        String accessTokenKey = "access:"+userId;
        redisService.delete(accessTokenKey);
        redisService.save(accessTokenKey,accessToken,Duration.ofMillis(ACCESS_TOKEN_TIME));
        return accessToken;
    }

    public String createRefreshToken(Long userId, String userName, Role role) {
        String refreshToken = this.createToken(userId, userName, role, REFRESH_TOKEN_TIME, "refresh");
        String refreshTokenKey = "refresh:"+userId;
        redisService.save(refreshTokenKey, refreshToken, Duration.ofMillis(REFRESH_TOKEN_TIME));
        return refreshToken;
    }

    public String substringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(7);
        }
        throw new ApplicationException(ErrorCode.INVALID_TOKEN);
    }

    public Claims extractClaims(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        log.info("JWT 검증 완료 - role: {}, tokenType: {}", claims.get("role"), claims.get("tokenType"));
        return claims;
    }

    public void validateToken(String refreshToken, String userId) {
        try {
            String redisToken = redisService.get("refresh:"+userId);
            if (!refreshToken.equals(substringToken(redisToken))) {
                throw new ApplicationException(ErrorCode.INVALID_TOKEN);
            }
            Jwts.parser().verifyWith(key).build().parse(refreshToken);
        } catch (ExpiredJwtException e) {
            throw new ApplicationException(ErrorCode.EXPIRED_TOKEN);
        } catch (JwtException e) {
            throw new ApplicationException(ErrorCode.INVALID_TOKEN);
        }
    }

}
