package br.com.nitertech.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import br.com.nitertech.jwt.dto.AuthenticationOutputDTO;
import br.com.nitertech.jwt.util.StringPair;
import jakarta.servlet.ServletException;

import static br.com.nitertech.jwt.Constants.*;

public class AppTest extends BaseTest
{
    @Test
    public void shouldAuthenticateInAuthRoute() throws ServletException, IOException
    {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        String subject = "test@gmail.com";

        req.setRequestURI(AUTH_ROUTE);
        req.setMethod(HttpMethod.GET.name());

        when(this.authenticator.authenticate(req))
            .thenReturn(new AuthenticationOutputDTO(true, subject, Set.of(USER_ROLE)));

        this.jwtFilter.doFilter(req, res, filterChain);

        StringPair tokens = this.objMapper.readValue(res.getContentAsString(), StringPair.class);

        assertTrue(tokens.getFirst().length() > 15);
        assertTrue(tokens.getSecond().length() > 15);
    }

    @Test
    public void shouldRenewToken() throws ServletException, IOException
    {
        StringPair tokens = this.getTokens(Set.of(USER_ROLE));

        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(RENEWAL_ROUTE);
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

        req.setRequestURI(NO_AUTH_ROUTE);
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

        req.setRequestURI(USER_RESTRICTED_ROUTE);
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

        StringPair userTokens = this.getTokens(Set.of(USER_ROLE));
        StringPair adminTokens = this.getTokens(Set.of(ADMIN_ROLE));

        req.setRequestURI(USER_RESTRICTED_ROUTE);
        req2.setRequestURI(USER_RESTRICTED_ROUTE);

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

        StringPair userTokens = this.getTokens(Set.of(USER_ROLE));
        StringPair adminTokens = this.getTokens(Set.of(ADMIN_ROLE));

        req.setRequestURI(USER_RESTRICTED_ROUTE);
        req2.setRequestURI(USER_RESTRICTED_ROUTE);

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

        StringPair userTokens = this.getTokens(Set.of(USER_ROLE));
        StringPair adminTokens = this.getTokens(Set.of(ADMIN_ROLE));

        req.setRequestURI(ADMIN_RESTRICTED_ROUTE);
        req2.setRequestURI(ADMIN_RESTRICTED_ROUTE);

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
        StringPair tokens = this.getTokens(Set.of(USER_ROLE));
        
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(USER_RESTRICTED_ROUTE);
        req.setMethod(HttpMethod.GET.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s", tokens.getFirst()));

        Thread.sleep(TOKEN_DURATION_MILLIS + 1000);

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    public void shouldAcceptRenewedToken() throws ServletException, IOException
    {
        StringPair renewedTokens = this.getRenewedTokens(this.getTokens(Set.of(USER_ROLE)).getSecond());

        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(USER_RESTRICTED_ROUTE);
        req.setMethod(HttpMethod.GET.name());
        req.addHeader(HttpHeaders.AUTHORIZATION, String.format("Bearer %s",
            renewedTokens.getFirst()));

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.OK.value());
    }

    @Test
    public void shouldProcessCustomProtectedRoutes() throws ServletException, IOException
    {
        this.authService.protectRoute(CUSTOM_RESTRICTED_ROUTE,
            request -> request.getHeader("Is-Allowed").equalsIgnoreCase("yes"));

        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        req.setRequestURI(CUSTOM_RESTRICTED_ROUTE);
        req.addHeader("Is-Allowed", "yes");

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.OK.value());

        req = new MockHttpServletRequest();
        res = new MockHttpServletResponse();
        filterChain = new MockFilterChain();

        req.setRequestURI(CUSTOM_RESTRICTED_ROUTE);
        req.addHeader("Is-Allowed", "no");

        this.jwtFilter.doFilter(req, res, filterChain);

        assertEquals(res.getStatus(), HttpStatus.UNAUTHORIZED.value());
    }
}
