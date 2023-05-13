package com.nhnacademy.security.controller;

import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {
    @GetMapping("/")
    public String index(HttpServletRequest request, ModelMap modelMap) {
        modelMap.put("isLoggedIn", Objects.nonNull(request.getSession(false)));
        return "index";
    }

}
