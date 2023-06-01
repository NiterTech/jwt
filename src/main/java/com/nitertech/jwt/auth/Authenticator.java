package com.nitertech.jwt.auth;

import com.nitertech.jwt.dto.AuthenticationOutputDTO;

import jakarta.servlet.http.HttpServletRequest;

public interface Authenticator
{
    AuthenticationOutputDTO authenticate(HttpServletRequest req);
}
