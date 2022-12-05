package com.nhnacademy.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

// TODO #5: `/logout` 페이지에서 로그아웃을 구현합니다.
@Controller
public class LogoutController {
    @GetMapping("/logout")
    public String logout() {
        // TODO #5-1: 실습 - `SESSION` 쿠키를 삭제합니다.

        // TODO #5-2: 실습 - redis 에서 session 정보를 삭제합니다.

        // TODO #5-3: 실습 - `/login` 페이지로 redirect 합니다.
        return null;
    }

}
