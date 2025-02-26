package org.example.expert.config;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;


@Slf4j
@Component
@RequiredArgsConstructor
public class AdminInterceptor implements HandlerInterceptor {

    private final JwtUtil jwtUtil;

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {
        log.info("preHandle Start");
        String requestURI = request.getMethod();
        String method = request.getMethod();

        //어드민 권한 확인
        boolean isAdmin = checkAdminAuthroity(request);

        if (!isAdmin) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN,"관리자 권한이 필요합니다.");
            return false;
        }

        //요청시각과 URL 로깅
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE);
        log.info("관리자 API 접근 - TIME: {}, Method: {}, URL: {}", timestamp, method, requestURI);
        return true;
    }

    private boolean checkAdminAuthroity(HttpServletRequest request) {
        //TODO 세션이나 토큰을 통해 어드민 권한을 확인해야 함.
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = jwtUtil.substringToken(authHeader);
                Claims claims = jwtUtil.extractClaims(token);

                UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));
                return UserRole.ADMIN == userRole;
            }
        } catch (Exception e) {
            log.error("관리자 권한 체크 에러",e);
        }
        return false;
    }

}
