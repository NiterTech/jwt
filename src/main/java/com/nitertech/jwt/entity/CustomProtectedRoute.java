package com.nitertech.jwt.entity;

import com.nitertech.jwt.auth.CustomVerifier;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class CustomProtectedRoute
{
    private String pattern;
    private CustomVerifier verifier;
}
