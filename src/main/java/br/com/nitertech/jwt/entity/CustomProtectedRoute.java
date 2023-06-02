package br.com.nitertech.jwt.entity;

import br.com.nitertech.jwt.auth.CustomVerifier;
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
