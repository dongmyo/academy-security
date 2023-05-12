package com.nhnacademy.security.interceptor;

import com.nhnacademy.security.util.CookieUtils;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.servlet.HandlerInterceptor;

// TODO #10: 로그인된 사용자 정보를 redis 에서 읽어와서 request 속성 값으로 설정하는 interceptor 구현
public class SessionInterceptor implements HandlerInterceptor {
    private final RedisTemplate<String, Object> redisTemplate;

    public SessionInterceptor(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws Exception {
        String sessionId = CookieUtils.getCookieValue(request, "SESSION");
        if (Objects.nonNull(sessionId)) {
            String username = (String) redisTemplate.opsForHash().get(sessionId, "username");
            String authority = (String) redisTemplate.opsForHash().get(sessionId, "authority");

            request.setAttribute("username", username);
            request.setAttribute("authority", authority);
        }

        return true;
    }

}
