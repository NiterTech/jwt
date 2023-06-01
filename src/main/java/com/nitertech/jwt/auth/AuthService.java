package com.nitertech.jwt.auth;

import com.nitertech.jwt.entity.ProtectedRoute;
import com.nitertech.jwt.entity.Role;
import com.nitertech.jwt.util.RenewalTokenStore;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;
import java.util.Set;

import org.springframework.http.HttpMethod;

public interface AuthService
{
    AuthService setTokenStore(RenewalTokenStore store);
    AuthService protectRoute(String pattern, Set<HttpMethod> methodsAllowed, Set<Role> rolesAllowed);
    AuthService protectRoute(String pattern, CustomVerifier verifier);
    AuthService setAuthenticationRoute(String pattern);
    AuthService setRenewalRoute(String pattern);
    boolean isRouteProtected(HttpServletRequest request);
    boolean isAllowed(HttpServletRequest request);
    HttpServletResponse authenticate(HttpServletRequest request, HttpServletResponse response);
    HttpServletResponse renewToken(HttpServletRequest request, HttpServletResponse response);
    boolean isAuthRoute(HttpServletRequest request);
    boolean isRenewalRoute(HttpServletRequest request);
}
