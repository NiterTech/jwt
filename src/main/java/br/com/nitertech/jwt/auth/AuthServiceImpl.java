package br.com.nitertech.jwt.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.AntPathMatcher;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.nitertech.jwt.dto.AuthenticationOutputDTO;
import br.com.nitertech.jwt.entity.CustomProtectedRoute;
import br.com.nitertech.jwt.entity.ProtectedRoute;
import br.com.nitertech.jwt.entity.Role;
import br.com.nitertech.jwt.util.RenewalTokenStore;
import br.com.nitertech.jwt.util.StringPair;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthServiceImpl implements AuthService
{
    private final JWTVerifier jwtVerifier;
    private final String ROLES;
    private final String IS_RENEWAL_TOKEN;
    private final ObjectMapper objMapper = new ObjectMapper();
    private final Authenticator authenticator;
    private final String tokenKey;
    private final String tokenIssuer;
    private final Long tokenDurationMillis;
    private final Long renewTokenDurationMillis;
    private RenewalTokenStore tokenStore;
    private List<ProtectedRoute> protectedRoutes;
    private List<CustomProtectedRoute> customProtectedRoutes;
    private String authRoute;
    private String tokenRenewalRoute;

    public AuthServiceImpl(JWTVerifier jwtVerifier, Authenticator authenticator,
        RenewalTokenStore tokenStore, String tokenKey, String tokenIssuer,
        Long tokenDurationMillis, Long renewTokenDurationMillis)
    {
        this.jwtVerifier = jwtVerifier;
        this.authenticator = authenticator;
        this.tokenStore = tokenStore;
        this.tokenKey = tokenKey;
        this.tokenIssuer = tokenIssuer;
        this.tokenDurationMillis = tokenDurationMillis;
        this.renewTokenDurationMillis = renewTokenDurationMillis;
        this.ROLES = "roles";
        this.IS_RENEWAL_TOKEN = "isRenewalToken";
        this.protectedRoutes = new ArrayList<>();
        this.customProtectedRoutes = new ArrayList<>();
    }

    private Optional<CustomProtectedRoute> getCustomProtectedRoute(String pattern)
    {
        for (CustomProtectedRoute route : this.customProtectedRoutes)
            if (new AntPathMatcher().match(route.getPattern(), pattern))
                return Optional.of(route);

        return Optional.empty();
    }

    private Optional<ProtectedRoute> getProtectedRoute(HttpServletRequest request)
    {
        for (ProtectedRoute route : this.protectedRoutes)
            for (HttpMethod method : route.getProtectedMethods())
                if (new AntPathMatcher().match(route.getPattern(), request.getRequestURI())
                    && method.name().equalsIgnoreCase(request.getMethod()))
                return Optional.of(route);

        return Optional.empty();
    }

    private Optional<DecodedJWT> getToken(HttpServletRequest request)
    {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (token.length() == 0 || token.length() < 15)
            return Optional.empty();

        try
        {
            return Optional.of(this.jwtVerifier.verify(request.getHeader(HttpHeaders.AUTHORIZATION)
                .split("Bearer ")[1]));
        }
        catch (Exception e)
        {
            return Optional.empty();
        }
    }

    private StringPair generateTokens(String subject, Set<Role> roles) throws JsonProcessingException,
        IllegalArgumentException, JWTCreationException
    {
        String token = JWT.create()
            .withIssuer(this.tokenIssuer)
            .withClaim(ROLES, this.objMapper.writeValueAsString(roles))
            .withSubject(subject)
            .withIssuedAt(new Date())
            .withExpiresAt(new Date(System.currentTimeMillis() + this.tokenDurationMillis))
            .withJWTId(UUID.randomUUID().toString())
            .withNotBefore(new Date(System.currentTimeMillis()))
            .sign(Algorithm.HMAC256(this.tokenKey));

        String renovationToken = JWT.create()
            .withIssuer(this.tokenIssuer)
            .withClaim(ROLES, this.objMapper.writeValueAsString(roles))
            .withSubject(subject)
            .withIssuedAt(new Date())
            .withExpiresAt(new Date(System.currentTimeMillis() + this.renewTokenDurationMillis))
            .withJWTId(UUID.randomUUID().toString())
            .withNotBefore(new Date(System.currentTimeMillis()))
            .sign(Algorithm.HMAC256(this.tokenKey));

        this.tokenStore.saveToken(renovationToken);
        
        return new StringPair(token, renovationToken);
    }

    private boolean isRenewalTokenValid(String token)
    {
        return this.tokenStore.exists(token);
    }

    private StringPair getNewTokens(String oldRenovationToken) throws JsonMappingException,
        JsonProcessingException, IllegalArgumentException, JWTCreationException
    {
        DecodedJWT decodedToken = JWT.decode(oldRenovationToken);

        StringPair newTokens = this.generateTokens(decodedToken.getSubject(),
            this.objMapper.readValue(decodedToken.getClaim(ROLES).asString(),
                new TypeReference<Set<Role>>(){}));

        this.tokenStore.deleteToken(oldRenovationToken);
        this.tokenStore.saveToken(newTokens.getSecond());
        
        return newTokens;
    }

    @Override
    public AuthService setTokenStore(RenewalTokenStore store)
    {
        this.tokenStore = store;
        return this;
    }

    @Override
    public AuthService protectRoute(String pattern, Set<HttpMethod> methodsAllowed, Set<Role> rolesAllowed)
    {
        this.protectedRoutes.add(new ProtectedRoute(pattern, methodsAllowed, rolesAllowed));
        return this;
    }

    @Override
    public AuthService protectRoute(String pattern, CustomVerifier verifier)
    {
        this.customProtectedRoutes.add(new CustomProtectedRoute(pattern, verifier));
        return this;
    }

    @Override
    public AuthService setAuthenticationRoute(String pattern)
    {
        this.authRoute = pattern;
        return this;
    }

    @Override
    public AuthService setRenewalRoute(String pattern)
    {
        this.tokenRenewalRoute = pattern;
        return this;
    }

    @Override
    public boolean isRouteProtected(HttpServletRequest request)
    {
        if (this.getProtectedRoute(request).isPresent())
            return true;
        
        for (CustomProtectedRoute route : this.customProtectedRoutes)
            if (new AntPathMatcher().match(route.getPattern(), request.getRequestURI()))
                return true;

        return false;
    }

    @Override
    public boolean isAllowed(HttpServletRequest request)
    {
        if (this.getCustomProtectedRoute(request.getRequestURI()).isPresent())
            return this.getCustomProtectedRoute(request.getRequestURI()).get().getVerifier()
                .isAllowed(request);
        
        ProtectedRoute route = this.getProtectedRoute(request).get();

        if (this.getToken(request).isEmpty())
            return false;

        DecodedJWT token = this.getToken(request).get();

        try
        {
            Set<Role> roles = this.objMapper.readValue(token.getClaim(ROLES).asString(),
                new TypeReference<Set<Role>>() {});

            for (Role reqRole : roles)
                for (Role allowedRole : route.getAllowedRoles())
                    if (allowedRole.getName().equalsIgnoreCase(reqRole.getName()))
                        return true;
        }
        catch (Exception e)
        {
            return false;
        }

        return false;
    }

    @Override
    public HttpServletResponse authenticate(HttpServletRequest request, HttpServletResponse response)
    {
        AuthenticationOutputDTO output = this.authenticator.authenticate(request);

        if (output.success)
        {
            response.setStatus(HttpStatus.OK.value());
            response.setContentType(MediaType.APPLICATION_JSON.getType());
            try
            {
                response.getWriter().write(this.objMapper.writeValueAsString(this.generateTokens(output.subject, output.roles)));
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        else
        {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }

        return response;
    }

    @Override
    public HttpServletResponse renewToken(HttpServletRequest request, HttpServletResponse response)
    {
        String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (auth.split("Bearer ").length == 0 || auth.split("Bearer ")[1].length() < 15 ||
            !this.isRenewalTokenValid(auth.split("Bearer ")[1]))
        {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return response;
        }

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON.getType());
        try
        {
            response.getWriter().write(this.objMapper.writeValueAsString(this.getNewTokens(
                auth.split("Bearer ")[1])));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        
        return response;
    }

    @Override
    public boolean isAuthRoute(HttpServletRequest request)
    {
        return new AntPathMatcher().match(this.authRoute, request.getRequestURI());
    }

    @Override
    public boolean isRenewalRoute(HttpServletRequest request)
    {
        return new AntPathMatcher().match(this.tokenRenewalRoute, request.getRequestURI());
    }
}
