package br.com.nitertech.jwt.dto;

import java.util.Set;

import br.com.nitertech.jwt.entity.Role;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationOutputDTO
{
    public boolean success;
    public String subject;
    public Set<Role> roles;
}
