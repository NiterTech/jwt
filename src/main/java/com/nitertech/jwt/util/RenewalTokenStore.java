package com.nitertech.jwt.util;

public interface RenewalTokenStore
{
    void deleteToken(String token);
    void saveToken(String token);
    boolean exists(String token);
}
