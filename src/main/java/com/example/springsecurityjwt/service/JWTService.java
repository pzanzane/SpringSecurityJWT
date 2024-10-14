package com.example.springsecurityjwt.service;


import io.jsonwebtoken.Jwts;

import java.util.HashMap;
import java.util.Map;

/**
 * Responsible to generate the JWT Token.
 */
public class JWTService {

    /**
     * Responsible to generate JWT token with empty claims.
     * @return Returns JWT token as a String.
     */
    public String generateToken() {
        return generateToken(new HashMap<>());
    }

    /**
     * Responsible to generate JWT token with claims.
     * @return Returns JWT token as a String.
     */
    public String generateToken(Map<String, Object> extraClaims) {
        return buildToken(extraClaims);
    }

    private String buildToken(Map<String, Object> extraClaims) {
        return "";
    }
}
