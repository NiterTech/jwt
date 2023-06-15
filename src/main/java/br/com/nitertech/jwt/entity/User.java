package br.com.nitertech.jwt.entity;

public interface User
{
    boolean hasSpecialRenewalTokenDuration();
    void toggleSpecialRenewalTokenDuration(boolean state);
}