package com.bej.authenticationservice.filter;

import io.jsonwebtoken.Jwts;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class JwtFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        ServletOutputStream pw = httpServletResponse.getOutputStream();
        String authHeader = httpServletRequest.getHeader("Authorization");
        if(authHeader == null || !authHeader.startsWith("Bearer")){
            httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            pw.println("Invalid or Missing Token");
            pw.close();
        }
        else{
            String jwtToken = authHeader.substring(7);
            String userName = Jwts.parser().setSigningKey("secretKey").parseClaimsJws(jwtToken).getBody().getSubject();
            httpServletRequest.setAttribute("userName",userName);
            filterChain.doFilter(servletRequest,servletResponse);
        }
    }
}
