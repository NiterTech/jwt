package br.com.nitertech.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
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

@ExtendWith(MockitoExtension.class)
public class AppTest
{
    private String key;
    private String issuer;
    private String authRoute;
    private String renewalRoute;
    private String noAuthRoute;
    private String userRestrictedRoute;
    private String adminRestrictedRoute;
    private String customRestrictedRoute;
    private Long tokenDurationMillis;
    private Long renewalTokenDurationMillis;
    private AuthService authService;
    private Role user, admin;

    private ObjectMapper objMapper = new ObjectMapper();

    private JwtFilter jwtFilter;

    @Mock
    private Authenticator authenticator;

    @Mock
    private RenewalTokenStore store;

    @BeforeEach
    public void setup()
    {
        this.user = new Role("User");
        this.admin = new Role("ADMIN");
        this.key = "testKey";
        this.issuer = "testIssuer";
        this.authRoute = "/api/v1.0/auth/login";
        this.renewalRoute = "/api/v1.0/auth/renew";
        this.noAuthRoute = "/api/v1.0/noauth";
        this.userRestrictedRoute = "/api/v1.0/user";
        this.adminRestrictedRoute = "/api/v1.0/admin";
        this.customRestrictedRoute = "/api/v1.0/custom";
        this.tokenDurationMillis = 10L * 1000;
        this.renewalTokenDurationMillis = 20L * 1000;

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(key)).withIssuer(this.issuer).build();

        this.authService = new AuthServiceImpl(verifier, authenticator, store, this.key, this.issuer,
            this.tokenDurationMillis, this.renewalTokenDurationMillis)
            .setAuthenticationRoute(this.authRoute)
            .setRenewalRoute(this.renewalRoute)
            .protectRoute(this.userRestrictedRoute, Set.of(HttpMethod.GET), Set.of(this.user, this.admin))
            .protectRoute(this.userRestrictedRoute, Set.of(HttpMethod.POST), Set.of(this.admin))
            .protectRoute(this.adminRestrictedRoute, Set.of(HttpMethod.GET, HttpMethod.POST),
                Set.of(this.admin));

        this.jwtFilter = new JwtFilter(this.authService);
    }

    private StringPair getTokens(Set<Role> desiredRoles) throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        String subject = "test@gmail.com";

        req.setRequestURI(this.authRoute);
        req.setMethod(HttpMethod.POST.name());

        when(this.authenticator.authenticate(req))
            .thenReturn(new AuthenticationOutputDTO(true, subject, desiredRoles));

        this.jwtFilter.doFilter(req, res, filterChain);

        return this.objMapper.readValue(res.getContentAsString(), StringPair.class);
    }

    private StringPair getRenewedTokens(String renovationToken) throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(this.renewalRoute);
        req.setMethod(HttpMethod.POST.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", renovationToken));

        when(this.store.exists(any())).thenReturn(true);

        this.jwtFilter.doFilter(req, res, filterChain);

        return this.objMapper.readValue(res.getContentAsString(), StringPair.class);
    }

    @Test
    public void shouldAuthenticateInAuthRoute() throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        String subject = "test@gmail.com";

        req.setRequestURI(this.authRoute);
        req.setMethod(HttpMethod.GET.name());

        when(this.authenticator.authenticate(req))
            .thenReturn(new AuthenticationOutputDTO(true, subject, Set.of(this.user)));

        this.jwtFilter.doFilter(req, res, filterChain);

        StringPair tokens = this.objMapper.readValue(res.getContentAsString(), StringPair.class);

        assertTrue(tokens.getFirst().length() > 15);
        assertTrue(tokens.getSecond().length() > 15);
    }

    @Test
    public void shouldRenewToken() throws ServletException, IOException
    {
        StringPair tokens = this.getTokens(Set.of(this.user));

        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(this.renewalRoute);
        req.setMethod(HttpMethod.GET.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", tokens.getSecond()));

        when(this.store.exists(any())).thenReturn(true);

        this.jwtFilter.doFilter(req, res, filterChain);

        StringPair newTokens = this.objMapper.readValue(res.getContentAsString(), StringPair.class);

        assertTrue(newTokens.getFirst().length() > 15);
        assertTrue(newTokens.getSecond().length() > 15);
    }

    @Test
    public void shouldAllowAnonymousInUnprotectedRoute() throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(this.noAuthRoute);
        req.setMethod(HttpMethod.GET.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, "");

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.OK.value());
    }

    @Test
    public void shouldNotAllowAnonymousInProtectedRoutes() throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(this.userRestrictedRoute);
        req.setMethod(HttpMethod.GET.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, "");

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    public void shouldAllowUserAndAdminInProtectedRoute() throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest(), req2 = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse(), res2 = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain(), filterChain2 = new MockFilterChain();

        StringPair userTokens = this.getTokens(Set.of(this.user));
        StringPair adminTokens = this.getTokens(Set.of(this.admin));

        req.setRequestURI(this.userRestrictedRoute);
        req2.setRequestURI(this.userRestrictedRoute);

        req.setMethod(HttpMethod.GET.name());
        req2.setMethod(HttpMethod.GET.name());

        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", userTokens.getFirst()));
        req2.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", adminTokens.getFirst()));

        this.jwtFilter.doFilter(req, res, filterChain);
        this.jwtFilter.doFilter(req2, res2, filterChain2);

        assertEquals(res.getStatus(), HttpStatus.OK.value());
        assertEquals(res2.getStatus(), HttpStatus.OK.value());
    }

    @Test
    public void shouldAllowOnlyAdminInPOSTInProtectedRoute() throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest(), req2 = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse(), res2 = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain(), filterChain2 = new MockFilterChain();

        StringPair userTokens = this.getTokens(Set.of(this.user));
        StringPair adminTokens = this.getTokens(Set.of(this.admin));

        req.setRequestURI(this.userRestrictedRoute);
        req2.setRequestURI(this.userRestrictedRoute);

        req.setMethod(HttpMethod.POST.name());
        req2.setMethod(HttpMethod.POST.name());

        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", userTokens.getFirst()));
        req2.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", adminTokens.getFirst()));

        this.jwtFilter.doFilter(req, res, filterChain);
        this.jwtFilter.doFilter(req2, res2, filterChain2);

        assertEquals(res.getStatus(), HttpStatus.UNAUTHORIZED.value());
        assertEquals(res2.getStatus(), HttpStatus.OK.value());
    }

    @Test
    public void shouldAllowAdminOnlyInAdminRestrictedRoute() throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest(), req2 = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse(), res2 = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain(), filterChain2 = new MockFilterChain();

        StringPair userTokens = this.getTokens(Set.of(this.user));
        StringPair adminTokens = this.getTokens(Set.of(this.admin));

        req.setRequestURI(this.adminRestrictedRoute);
        req2.setRequestURI(this.adminRestrictedRoute);

        req.setMethod(HttpMethod.GET.name());
        req2.setMethod(HttpMethod.GET.name());

        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", userTokens.getFirst()));
        req2.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", adminTokens.getFirst()));

        this.jwtFilter.doFilter(req, res, filterChain);
        this.jwtFilter.doFilter(req2, res2, filterChain2);

        assertEquals(res.getStatus(), HttpStatus.UNAUTHORIZED.value());
        assertEquals(res2.getStatus(), HttpStatus.OK.value());
    }

    @Test
    public void shouldNotAllowExpiredTokens() throws ServletException, IOException, InterruptedException
    {
        StringPair tokens = this.getTokens(Set.of(this.user));
        
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(this.userRestrictedRoute);
        req.setMethod(HttpMethod.GET.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", tokens.getFirst()));

        Thread.sleep(this.tokenDurationMillis + 1000);

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    public void shouldAcceptRenewedToken() throws ServletException, IOException
    {
        StringPair renewedTokens = this.getRenewedTokens(this.getTokens(Set.of(this.user)).getSecond());

        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(this.userRestrictedRoute);
        req.setMethod(HttpMethod.GET.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s",
            renewedTokens.getFirst()));

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.OK.value());
    }

    @Test
    public void shouldProcessCustomProtectedRoutes() throws ServletException, IOException
    {
        this.authService.protectRoute(this.customRestrictedRoute,
            request -> request.getHeader("Is-Allowed").equalsIgnoreCase("yes"));

        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(this.customRestrictedRoute);
        req.addHeader("Is-Allowed", "yes");

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.OK.value());

        req = new MockHttpServletRequest();
        res = new MockHttpServletResponse();
        filterChain = new MockFilterChain();

        req.setRequestURI(this.customRestrictedRoute);
        req.addHeader("Is-Allowed", "no");

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.UNAUTHORIZED.value());
    }
}
