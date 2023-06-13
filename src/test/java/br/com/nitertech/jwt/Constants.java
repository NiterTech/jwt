package br.com.nitertech.jwt;

import br.com.nitertech.jwt.entity.Role;

public class Constants
{
    private static final String API_BASE_ROUTE = "/api/v1.0/";
    public static final String KEY = "testKey";
    public static final String ISSUER = "testIssuer";
    public static final String AUTH_ROUTE = API_BASE_ROUTE + "auth/login";
    public static final String RENEWAL_ROUTE = API_BASE_ROUTE + "auth/renew";
    public static final String NO_AUTH_ROUTE = API_BASE_ROUTE + "noauth";
    public static final String USER_RESTRICTED_ROUTE = API_BASE_ROUTE + "user";
    public static final String ADMIN_RESTRICTED_ROUTE = API_BASE_ROUTE + "admin";
    public static final String CUSTOM_RESTRICTED_ROUTE = API_BASE_ROUTE + "custom";
    public static final Long TOKEN_DURATION_MILLIS = 10L * 1000;
    public static final Long RENEWAL_TOKEN_DURATION_MILLIS = 20L * 1000;
    public static final Role USER_ROLE = new Role("User");
    public static final Role ADMIN_ROLE = new Role("Admin");
}
