package br.com.nitertech.jwt;

import java.io.IOException;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import br.com.nitertech.jwt.entity.User;
import br.com.nitertech.jwt.util.StringPair;
import jakarta.servlet.ServletException;

import static br.com.nitertech.jwt.Constants.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenDurationTest extends BaseTest
{
    private User user, admin;
    
    @Override
    public void setup()
    {
        super.setup();

        this.user = new UserImpl(false);
    }

    @Test
    public void renewTokenTimesShouldBeAbleToBeDifferentBetweenUsers() throws ServletException, IOException // Useful for "Remember Me"
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        StringPair userTokens = this.getTokens(Set.of(USER_ROLE));

        req.setRequestURI(USER_RESTRICTED_ROUTE);

        req.setMethod(HttpMethod.GET.name());

        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", userTokens.getFirst()));

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.OK.value());
    }
}
