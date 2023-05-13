package com.nhnacademy.security.controller;

import java.util.Arrays;
import java.util.Objects;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

// TODO #5: `/logout` 페이지에서 로그아웃을 구현합니다.
@Controller
public class LogoutController {
    private final RedisTemplate<String, Object> redisTemplate;

    public LogoutController(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


    @GetMapping("/logout")
    public String logout(HttpServletRequest request,
                         HttpServletResponse response) {
        Cookie cookie = Arrays.stream(request.getCookies())
            .filter(c -> c.getName().equals("SESSION"))
            .findFirst()
            .orElse(null);

        if (Objects.nonNull(cookie)) {
            // TODO #5-1: 실습 - `SESSION` 쿠키를 삭제합니다.
            String sessionId = cookie.getValue();

            cookie.setMaxAge(0);
            response.addCookie(cookie);

            // TODO #5-2: 실습 - redis 에서 session 정보를 삭제합니다.
            redisTemplate.opsForHash().delete(sessionId, "username", "authority");
        }

        // TODO #5-3: 실습 - `/login` 페이지로 redirect 합니다.
        return "redirect:/login";
    }

}
