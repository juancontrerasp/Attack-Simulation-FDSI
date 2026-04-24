package com.secureapp.dto;

public class AuthResponse {

    private final String token;
    private final String tokenType = "Bearer";
    private final long expiresIn;

    public AuthResponse(String token, long expiresIn) {
        this.token = token;
        this.expiresIn = expiresIn;
    }

    public String getToken() { return token; }
    public String getTokenType() { return tokenType; }
    public long getExpiresIn() { return expiresIn; }
}
