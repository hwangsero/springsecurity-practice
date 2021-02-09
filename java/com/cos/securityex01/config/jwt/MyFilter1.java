package com.cos.securityex01.config.jwt;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        if(req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization"); // header의 Authorization을 가져옴
        }

        System.out.println("필터1");
        filterChain.doFilter(req, res);

    }
}
