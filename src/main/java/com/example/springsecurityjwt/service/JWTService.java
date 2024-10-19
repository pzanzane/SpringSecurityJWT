package com.example.springsecurityjwt.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Responsible to generate the JWT Token.
 */
public class JWTService {

    @Value("${security.jwt.secret.key}")
    private String secretKey;


    @Value("${security.jwt.expiration-time}")
    private long jwtSecretExpiration;

    /**
     * Responsible to generate JWT token with empty claims.
     *
     * @return Returns JWT token as a String.
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Responsible to generate JWT token with claims.
     *
     * @return Returns JWT token as a String.
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, secretKey, jwtSecretExpiration);
    }

    public boolean isUserValid(final String token, final UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public boolean isTokenValid(final String token) {

        if (isTokenExpired(token)) {
            return false;
        }

        final String userName = extractUserName(token);

        if (Objects.isNull(userName) || Strings.isEmpty(userName)) {
            return false;
        }

        return true;
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String extractUserName(final String token) {
        return extractAllClaims(token).getSubject();
    }

    private String buildToken(Map<String, Object> extraClaims,
                              UserDetails userDetails,
                              String secretKey,
                              long expirationTime) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSignKey(secretKey), SignatureAlgorithm.ES256)
                .toString();
    }

    private Key getSignKey(String secretKey) {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }




    private Date extractExpiration(final String token) {
        return extractAllClaims(token).getExpiration();
    }

    /**
     * Parses a JWS token, Json Web Signature is a type of JWT which is signed by a key.
     * We need a Sign key to parse this encrypted payload which is nothing but the claims.
     *
     * @param jwsToken Json Web Signature.
     * @return  Payload part of JWS.
     */
    private Claims extractAllClaims(String jwsToken) {

        return Jwts.parserBuilder()
                .setSigningKey(getSignKey(secretKey))
                .build()
                .parseClaimsJws(jwsToken)
                .getBody();

    }
}
