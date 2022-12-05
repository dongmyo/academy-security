package com.nhnacademy.security.auth;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

// TODO #4: 실습 - login success handler를 구현하세요.
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private final RedisTemplate<String, Object> redisTemplate;


    public LoginSuccessHandler(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication)
        throws IOException, ServletException {
        String sessionId = UUID.randomUUID().toString();

        // TODO #4-1: `SESSION` 이라는 이름의 쿠키에 sessionId를 저장하세요.

        // TODO #4-2: redis에 session 정보를 저장하세요.
        String username = null;
        String authority = null;

        redisTemplate.opsForHash().put(sessionId, "username", username);
        redisTemplate.opsForHash().put(sessionId, "authority", authority);

        super.onAuthenticationSuccess(request, response, authentication);
    }

}
