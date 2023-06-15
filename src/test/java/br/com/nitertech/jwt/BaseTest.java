package br.com.nitertech.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.nitertech.jwt.auth.AuthService;
import br.com.nitertech.jwt.auth.AuthServiceImpl;
import br.com.nitertech.jwt.auth.Authenticator;
import br.com.nitertech.jwt.dto.AuthenticationOutputDTO;
import br.com.nitertech.jwt.entity.Role;
import br.com.nitertech.jwt.security.JwtFilter;
import br.com.nitertech.jwt.util.RenewalTokenStore;
import br.com.nitertech.jwt.util.StringPair;
import jakarta.servlet.ServletException;

import static br.com.nitertech.jwt.Constants.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Set;

@ExtendWith(MockitoExtension.class)
public class BaseTest
{
    protected AuthService authService;

    protected ObjectMapper objMapper = new ObjectMapper();

    protected JwtFilter jwtFilter;

    @Mock
    protected Authenticator authenticator;

    @Mock
    protected RenewalTokenStore store;

    @BeforeEach
    public void setup()
    {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(KEY)).withIssuer(ISSUER).build();

        this.authService = new AuthServiceImpl(verifier, authenticator, store, KEY, ISSUER,
            TOKEN_DURATION_MILLIS, RENEWAL_TOKEN_DURATION_MILLIS)
            .setAuthenticationRoute(AUTH_ROUTE)
            .setRenewalRoute(RENEWAL_ROUTE)
            .protectRoute(USER_RESTRICTED_ROUTE, Set.of(HttpMethod.GET), Set.of(USER_ROLE, ADMIN_ROLE))
            .protectRoute(USER_RESTRICTED_ROUTE, Set.of(HttpMethod.POST), Set.of(ADMIN_ROLE))
            .protectRoute(ADMIN_RESTRICTED_ROUTE, Set.of(HttpMethod.GET, HttpMethod.POST),
                Set.of(ADMIN_ROLE));

        this.jwtFilter = new JwtFilter(this.authService);
    }

    protected StringPair getTokens(Set<Role> desiredRoles) throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        String subject = "test@gmail.com";

        req.setRequestURI(AUTH_ROUTE);
        req.setMethod(HttpMethod.POST.name());

        when(this.authenticator.authenticate(req))
            .thenReturn(new AuthenticationOutputDTO(true, subject, desiredRoles));

        this.jwtFilter.doFilter(req, res, filterChain);

        return this.objMapper.readValue(res.getContentAsString(), StringPair.class);
    }

    protected StringPair getRenewedTokens(String renovationToken) throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(RENEWAL_ROUTE);
        req.setMethod(HttpMethod.POST.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", renovationToken));

        when(this.store.exists(any())).thenReturn(true);

        this.jwtFilter.doFilter(req, res, filterChain);

        return this.objMapper.readValue(res.getContentAsString(), StringPair.class);
    }
}
