package com.nitertech.jwt.auth;

import jakarta.servlet.http.HttpServletRequest;

public interface CustomVerifier
{
    boolean isAllowed(HttpServletRequest request);
}
