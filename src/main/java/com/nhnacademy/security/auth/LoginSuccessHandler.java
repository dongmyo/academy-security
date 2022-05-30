package com.nhnacademy.security.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

// TODO #7: login success handler 구현
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication)
        throws ServletException, IOException {
        super.onAuthenticationSuccess(request, response, authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        List<GrantedAuthority> authorities = new ArrayList<>(userDetails.getAuthorities());

        HttpSession session = request.getSession();
        session.setAttribute("username", userDetails.getUsername());
        session.setAttribute("authority", authorities.get(0).getAuthority());
    }
}
