package com.springauth.controller;

import com.springauth.dto.AuthResponse;
import com.springauth.dto.LoginRequest;
import com.springauth.dto.MeResponse;
import com.springauth.dto.RegisterRequest;
import com.springauth.entity.User;
import com.springauth.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
// Marks this class as a REST controller.
//
// Spring converts returned Java objects into JSON automatically.
@RequestMapping("/api/auth")
// Every endpoint in this controller begins with:
//
// /api/auth
@RequiredArgsConstructor
// Lombok generates a constructor for the final fields.
//
// Spring uses that constructor to inject AuthService.
public class AuthController {

    // Contains the authentication business logic:
    //
    // - Registering users
    // - Logging users in
    // - Refreshing access tokens
    // - Logging users out
    private final AuthService authService;

    // --------------------------------------------------
    // REGISTER
    // --------------------------------------------------

    @PostMapping("/register")
    // Handles:
    //
    // POST /api/auth/register
    public ResponseEntity<AuthResponse> register(

            // Read the request JSON and convert it
            // into a RegisterRequest object.
            //
            // @Valid tells Spring to validate the object
            // using annotations such as:
            //
            // @NotBlank
            // @Email
            // @Size
            @Valid @RequestBody RegisterRequest request,

            // Represents the HTTP response that will be
            // returned to the client.
            //
            // AuthService can use it to add a refresh-token
            // cookie to the response.
            HttpServletResponse response
    ) {

        // Pass the registration data and HTTP response
        // to AuthService.
        //
        // AuthService performs the actual work:
        //
        // 1. Check whether the email already exists.
        // 2. Encode the password.
        // 3. Save the new user.
        // 4. Create an access token.
        // 5. Create a refresh token.
        // 6. Add the refresh token cookie to the response.
        AuthResponse authResponse =
                authService.register(request, response);

        // Return:
        //
        // HTTP 200 OK
        //
        // with AuthResponse as JSON.
        return ResponseEntity.ok(authResponse);
    }

    // --------------------------------------------------
    // LOGIN
    // --------------------------------------------------

    @PostMapping("/login")
    // Handles:
    //
    // POST /api/auth/login
    public ResponseEntity<AuthResponse> login(

            // Read JSON login credentials and validate them.
            //
            // Example JSON:
            //
            // {
            //   "email": "user@example.com",
            //   "password": "password123"
            // }
            @Valid @RequestBody LoginRequest request,

            // Allows AuthService to add the refresh-token
            // cookie to the HTTP response.
            HttpServletResponse response
    ) {

        // AuthService authenticates the email and password.
        //
        // If authentication succeeds, it creates:
        //
        // - An access token
        // - A refresh token
        //
        // The refresh token is written to an HttpOnly cookie.
        AuthResponse authResponse =
                authService.login(request, response);

        // Return:
        //
        // HTTP 200 OK
        //
        // with the authentication result as JSON.
        return ResponseEntity.ok(authResponse);
    }

    // --------------------------------------------------
    // REFRESH ACCESS TOKEN
    // --------------------------------------------------

    @PostMapping("/refresh")
    // Handles:
    //
    // POST /api/auth/refresh
    public ResponseEntity<AuthResponse> refresh(

            // Read the refresh token from a cookie named:
            //
            // refreshToken
            //
            // We do not use @RequestBody because the refresh token
            // is not sent inside JSON.
            //
            // required = false means Spring allows the cookie
            // to be missing.
            //
            // If it is missing, refreshToken will be null.
            @CookieValue(
                    name = "refreshToken",
                    required = false
            )
            String refreshToken,

            // Allows AuthService to write a new refresh-token
            // cookie into the HTTP response.
            HttpServletResponse response
    ) {

        // AuthService:
        //
        // 1. Checks that the refresh token exists.
        // 2. Finds its database record.
        // 3. Checks whether it is revoked.
        // 4. Checks whether it is expired.
        // 5. Creates a new access token.
        // 6. May rotate the refresh token.
        // 7. Writes the new refresh cookie.
        AuthResponse authResponse =
                authService.refresh(refreshToken, response);

        // Return:
        //
        // HTTP 200 OK
        //
        // with a new access token.
        return ResponseEntity.ok(authResponse);
    }

    // --------------------------------------------------
    // LOGOUT
    // --------------------------------------------------

    @PostMapping("/logout")
    // Handles:
    //
    // POST /api/auth/logout
    public ResponseEntity<Void> logout(

            // Read the refresh token from the browser cookie.
            //
            // It may be null when the cookie is missing.
            @CookieValue(
                    name = "refreshToken",
                    required = false
            )
            String refreshToken,

            // Allows AuthService to clear the cookie
            // from the HTTP response.
            HttpServletResponse response
    ) {

        // AuthService usually:
        //
        // 1. Finds the refresh token in the database.
        // 2. Marks it as revoked.
        // 3. Clears the refresh-token cookie.
        authService.logout(refreshToken, response);

        // Return:
        //
        // HTTP 204 No Content
        //
        // There is no response body.
        return ResponseEntity
                .noContent()
                .build();
    }

    // --------------------------------------------------
    // CURRENT AUTHENTICATED USER
    // --------------------------------------------------

    @GetMapping("/me")
    // Handles:
    //
    // GET /api/auth/me
    //
    // This endpoint should require authentication.
    public ResponseEntity<MeResponse> me(

            // Inject the currently authenticated user's principal.
            //
            // Earlier, JwtAuthenticationFilter created:
            //
            // UsernamePasswordAuthenticationToken authToken =
            //     new UsernamePasswordAuthenticationToken(
            //         userDetails,
            //         null,
            //         userDetails.getAuthorities()
            //     );
            //
            // The filter then stored it inside:
            //
            // SecurityContextHolder
            //     .getContext()
            //     .setAuthentication(authToken);
            //
            // Because the principal is your User object,
            // Spring injects that User here.
            @AuthenticationPrincipal User user
    ) {

        // Create a response DTO using information
        // from the authenticated user.
        MeResponse meResponse =
                new MeResponse(
                        user.getId(),
                        user.getEmail(),
                        user.getRoles(),
                        user.isEnabled()
                );

        // Return:
        //
        // HTTP 200 OK
        //
        // with the current user's information as JSON.
        return ResponseEntity.ok(meResponse);
    }
}
