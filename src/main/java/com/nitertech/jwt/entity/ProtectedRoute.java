package com.nitertech.jwt.entity;

import java.util.Set;

import org.springframework.http.HttpMethod;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class ProtectedRoute
{
    private String pattern;
    private Set<HttpMethod> protectedMethods;
    private Set<Role> allowedRoles;
}
