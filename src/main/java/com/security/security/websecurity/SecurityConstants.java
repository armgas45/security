package com.security.security.websecurity;

public final class SecurityConstants {
    public static final long EXPIRATION_TIME = 1200000;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String REQUEST_HEADER = "Authorization";
    public static final String SIGN_UP_URL = "/users";
    public static final String JWT_SECRET_TOKEN = "very_secret_token";

    private SecurityConstants() {}
}
