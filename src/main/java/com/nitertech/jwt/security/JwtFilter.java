package com.nitertech.jwt.security;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import com.nitertech.jwt.auth.AuthService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtFilter extends OncePerRequestFilter
{
    private final AuthService authService;

    public JwtFilter(AuthService authService)
    {
        this.authService = authService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException
    {
        if (this.authService.isAuthRoute(request))
        {
            this.authService.authenticate(request, response);
            return;
        }

        if (this.authService.isRenewalRoute(request))
        {
            this.authService.renewToken(request, response);
            return;
        }

        if (this.authService.isRouteProtected(request) && !this.authService.isAllowed(request))
            return;

        filterChain.doFilter(request, response);
    }
}
