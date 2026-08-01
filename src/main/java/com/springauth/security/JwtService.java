package com.springauth.security;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Base64;


// The implementation of JWT methods
@Service
public class JwtService {

    // Secret key used to SIGN and VERIFY JWTs.
    // Only the server should know this key.
    private final SecretKey signingKey;

    private final long accessTokenExpirationMs;

    public JwtService(
            // To take the value from application.yml
            @Value("${app.jwt.secret}")
            String base64Secret,

            @Value("${app.jwt.access-token-expiration-ms}")
            long accessTokenExpirationMs) {

        // Convert the Base64 string into raw bytes.
        // Then build an HMAC signing key.
        //
        // JWT will use this key to:
        // 1. Sign newly created tokens.
        // 2. Verify received tokens.
        this.signingKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(base64Secret));

        this.accessTokenExpirationMs = accessTokenExpirationMs;
    }

    // Create a JWT access token for the authenticated user.
    public String generateAccessToken(UserDetails userDetails) {
        // Extract authorities from Spring Security.
        //
        // Example:
        //
        // [
        //     SimpleGrantedAuthority("ROLE_USER"),
        //     SimpleGrantedAuthority("ROLE_ADMIN")
        // ]
        List<String> roles = userDetails.getAuthorities().stream()
                // Convert every GrantedAuthority into its String.
                //
                // Example:
                // SimpleGrantedAuthority("ROLE_USER")
                // becomes
                // "ROLE_USER"
                .map(GrantedAuthority::getAuthority)
                // Collect everything into a List.
                .collect(Collectors.toList());

        // Java immediately creates a Date object containing the current date and time at that exact moment.
        Date now = new Date();

        // Get the expiry date
        Date expiry = new Date(now.getTime() + accessTokenExpirationMs);

        // Build the JWT.
        return Jwts.builder()
                // payload
                .subject(userDetails.getUsername())

                // Custom claim.
                // Claims are extra information stored in the JWT.
                // Here we store user roles.
                // roles:
                // [
                //     "ROLE_USER"
                // ]
                .claim("roles", roles)

                // issuedAt and expiration expect a Date object
                .issuedAt(now)
                .expiration(expiry)

                // Sign the JWT using our secret key.
                // This generates the signature.
                // If someone modifies the JWT later,
                // the signature verification will fail.
                .signWith(signingKey)

                // Convert everything into the final JWT String.
                // Example:
                // eyJhbGciOiJIUzI1NiJ9...
                .compact();
    }

    // Extracts the subject (email) from a token without checking expiry
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    // Check whether a JWT is valid.
    // Validation includes:
    // - Signature
    // - Expiration
    // - Format
    public boolean isTokenValid(String token) {
        try {
            // Parse the JWT.
            // If parsing succeeds,
            // the JWT is considered valid.
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // Parse the JWT and return its claims.
    // Claims contain:
    // - subject
    // - expiration
    // - issuedAt
    // - roles
    private Claims parseClaims(String token) {
        return Jwts.parser()
                // Tell JJWT which key should be used
                // to verify the JWT signature.
                .verifyWith(signingKey)
                // Build the parser.
                .build()
                // Parse the JWT.
                // During this step JJWT verifies:
                // - Signature
                // - Expiration
                // - JWT format
                .parseSignedClaims(token)
                // Return only the payload (claims).
                .getPayload();
    }
}
