package com.springbootjwt.common.jwt;

import com.springbootjwt.common.exception.ApplicationException;
import com.springbootjwt.common.exception.ErrorCode;
import com.springbootjwt.common.service.RedisService;
import com.springbootjwt.domain.user.dto.AuthUser;
import com.springbootjwt.domain.user.enums.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final RedisService redisService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest httpRequest,
            @NonNull HttpServletResponse httpResponse,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {
        String authorizationHeader = httpRequest.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String jwt = jwtUtil.substringToken(authorizationHeader);
            try {
                Claims claims = jwtUtil.extractClaims(jwt);
                String tokenType = claims.get("tokenType", String.class);
                String redisAccessToken = redisService.get("access:" + claims.getSubject());

                if ("refresh".equals(tokenType)) {
                    throw new ApplicationException(ErrorCode.REFRESH_TOKEN_FORBIDDEN);
                }

                if(redisAccessToken == null || !jwt.equals(jwtUtil.substringToken(redisAccessToken))) {
                    throw new ApplicationException(ErrorCode.INVALID_TOKEN);
                }

                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    setAuthentication(claims);
                }
            } catch (SecurityException | MalformedJwtException e) {
                throw new ApplicationException(ErrorCode.INVALID_TOKEN);
            } catch (ExpiredJwtException e) {
                throw new ApplicationException(ErrorCode.EXPIRED_TOKEN);
            } catch (UnsupportedJwtException e) {
                throw new ApplicationException(ErrorCode.UNSUPPORTED_TOKEN);
            } catch (ApplicationException e) {
                throw e;
            } catch (Exception e) {
                throw new ApplicationException(ErrorCode.EXCEPTION);
            }
        }
        chain.doFilter(httpRequest, httpResponse);
    }

    private void setAuthentication(Claims claims) {
        Long id = Long.valueOf(claims.getSubject());
        String userName = claims.get("userName", String.class);
        Role role = Role.of(claims.get("role", String.class));

        AuthUser authUser = new AuthUser(id, userName, role);
        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(authUser);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }
}
