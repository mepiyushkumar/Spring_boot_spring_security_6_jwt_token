package com.example.spring_security_jwt.config;

import com.example.spring_security_jwt.service.JwtService;
import com.example.spring_security_jwt.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Security;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmNkIiwiZXhwIjoxNzI4ODI3MTI1LCJpYXQiOjE3Mjg4MjM1MjV9.sH4UWn2UG8maMs0NYxxG6yGiYu57oMR-hpqst_B8LoI
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String userId = null;

        if(authHeader!=null && authHeader.startsWith("Bearer ")){
            token = authHeader.substring(7);
            userId = jwtService.extractUserId(token);
        }

        if(userId!=null && SecurityContextHolder.getContext().getAuthentication()==null){

            UserDetails userDetails = myUserDetailsService.loadUserByUsername(userId);

            if(jwtService.validateToken(token,userDetails)){
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);


            }
        }

        filterChain.doFilter(request,response);
    }
}
