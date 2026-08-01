package com.springauth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Using @Component spring boot register this filter as a Spring Bean so Spring can manage and inject it.
@Component
// Lombok generates a constructor containing all final fields.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // Used to validate the JWT and extract the user's email from it.
    private final JwtService jwtService;

    // Used to load the current user from the database by email.
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(

            // The incoming HTTP request.
            HttpServletRequest request,

            // The HTTP response that will eventually be sent to the client.
            HttpServletResponse response,

            // Represents the remaining filters in Spring Security's filter chain.
            FilterChain filterChain

    ) throws ServletException, IOException {

        // Read the "Authorization" header from the incoming request.
        //
        // Example:
        // Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
        String authHeader = request.getHeader("Authorization");

        // Check whether the Authorization header:
        //
        // 1. Exists
        // 2. Starts with "Bearer "
        //
        // If there is no Bearer token, we do not authenticate the request here.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {

            // Continue to the next filter.
            //
            // We do not automatically reject the request because the endpoint
            // might be public, such as:
            //
            // /auth/login
            // /auth/register
            // /health
            filterChain.doFilter(request, response);

            // Stop executing the rest of this method.
            return;
        }

        // Remove the first seven characters:
        //
        // "Bearer "
        //
        // "Bearer " contains 7 characters, including the space.
        //
        // Before:
        // Bearer eyJhbGciOiJIUzI1NiJ9...
        //
        // After:
        // eyJhbGciOiJIUzI1NiJ9...
        String jwt = authHeader.substring(7);

        // Check whether the JWT:
        //
        // - Has a valid signature
        // - Has not expired
        // - Has a valid structure
        if (!jwtService.isTokenValid(jwt)) {

            // The token is invalid or expired.
            //
            // We do not add authentication to the SecurityContext.
            //
            // We continue the request as an anonymous request.
            filterChain.doFilter(request, response);

            // Stop executing this method.
            return;
        }

        // Read the JWT subject.
        //
        // In this application, the subject contains the user's email.
        String email = jwtService.extractUsername(jwt);

        // Check whether another filter has already authenticated this request.
        //
        // If getAuthentication() is null, nobody has authenticated it yet.
        if (SecurityContextHolder
                .getContext()
                .getAuthentication() == null) {

            // Load the latest user information from the database.
            //
            // This returns a UserDetails object containing:
            //
            // - Username/email
            // - Encoded password
            // - Roles/authorities
            // - Enabled status
            // - Locked status
            UserDetails userDetails =
                    userDetailsService.loadUserByUsername(email);

            // Check the user's current database state.
            //
            // Even if their JWT is valid, a disabled account should not
            // be authenticated.
            if (userDetails.isEnabled()) {

                // Create Spring Security's Authentication object.
                //
                // This object represents the authenticated user
                // for the current HTTP request.
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(

                                // Principal:
                                // The identity of the authenticated user.
                                userDetails,

                                // Credentials:
                                // Usually the password during login.
                                //
                                // We use null because the JWT has already
                                // proved the request's identity. We do not
                                // need to check the password again.
                                null,

                                // Authorities:
                                // The roles and permissions of the user.
                                //
                                // Example:
                                // ROLE_USER
                                // ROLE_ADMIN
                                userDetails.getAuthorities()
                        );

                // Add extra request information to the authentication object.
                //
                // This can include details such as:
                //
                // - Remote IP address
                // - Session ID
                authToken.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request)
                );

                // Store the authenticated user in Spring Security's context.
                //
                // From this point onward, Spring considers the current
                // request authenticated.
                SecurityContextHolder
                        .getContext()
                        .setAuthentication(authToken);
            }
        }

        // Continue to the next filter.
        //
        // Eventually, if all filters allow it, the request reaches
        // the controller.
        filterChain.doFilter(request, response);
    }
}