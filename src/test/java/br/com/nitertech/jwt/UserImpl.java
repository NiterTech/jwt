package br.com.nitertech.jwt;

import br.com.nitertech.jwt.entity.User;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public class UserImpl implements User
{
    private boolean specialRenewalTokenDuration;

    @Override
    public boolean hasSpecialRenewalTokenDuration()
    {
        return this.specialRenewalTokenDuration;
    }

    @Override
    public void toggleSpecialRenewalTokenDuration(boolean state)
    {
        this.specialRenewalTokenDuration = state;
    }
}
