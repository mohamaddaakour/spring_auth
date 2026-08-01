package com.springauth.config;

import com.springauth.security.CustomUserDetailsService;
import com.springauth.security.JwtAuthenticationFilter;
import com.springauth.security.RestAccessDeniedHandler;
import com.springauth.security.RestAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
// Marks this class as a Spring configuration class.
// Spring scans it and executes every method annotated with @Bean.
@EnableWebSecurity
// Enables Spring Security for web applications.
@EnableMethodSecurity
// Enables annotations like:
//
// @PreAuthorize("hasRole('ADMIN')")
// @PostAuthorize(...)
@RequiredArgsConstructor
// Lombok generates a constructor containing every final field.
// Spring uses that constructor for dependency injection.
public class SecurityConfig {

    // Custom JWT filter that authenticates requests using Bearer tokens.
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // Handles authentication failures (401 Unauthorized).
    private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;

    // Handles authorization failures (403 Forbidden).
    private final RestAccessDeniedHandler restAccessDeniedHandler;

    @Bean
    // Creates Spring Security's filter chain.
    //
    // Every HTTP request passes through this chain
    // before reaching a controller.
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http

                // ---------------------------
                // CORS CONFIGURATION
                // ---------------------------
                //
                // Allows our frontend
                // (http://localhost:3000)
                // to communicate with this backend.
                .cors(cors ->
                        cors.configurationSource(corsConfigurationSource())
                )

                // ---------------------------
                // CSRF
                // ---------------------------
                //
                // Disabled because we are building
                // a stateless REST API using JWT.
                //
                // Access tokens are sent manually
                // inside the Authorization header.
                //
                // Authorization: Bearer <jwt>
                //
                // Therefore CSRF protection is
                // usually unnecessary.
                .csrf(csrf -> csrf.disable())

                // ---------------------------
                // SESSION MANAGEMENT
                // ---------------------------
                //
                // Never create HTTP sessions.
                //
                // Every request must authenticate
                // itself using its JWT.
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                // ---------------------------
                // EXCEPTION HANDLING
                // ---------------------------
                //
                // Replace Spring Security's default
                // HTML error pages with our JSON responses.
                .exceptionHandling(ex -> ex

                        // Used when the user is NOT authenticated.
                        //
                        // Example:
                        //
                        // - No JWT
                        // - Invalid JWT
                        // - Expired JWT
                        //
                        // Returns:
                        //
                        // HTTP 401
                        .authenticationEntryPoint(
                                restAuthenticationEntryPoint
                        )

                        // Used when the user IS authenticated
                        // but lacks permission.
                        //
                        // Example:
                        //
                        // ROLE_USER
                        //
                        // tries to access:
                        //
                        // ROLE_ADMIN endpoint
                        //
                        // Returns:
                        //
                        // HTTP 403
                        .accessDeniedHandler(
                                restAccessDeniedHandler
                        )
                )

                // ---------------------------
                // AUTHORIZATION RULES
                // ---------------------------
                //
                // Rules are evaluated
                // from top to bottom.
                .authorizeHttpRequests(auth -> auth

                        // Public endpoints.
                        //
                        // No authentication required.
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/refresh",
                                "/h2-console/**"
                        )
                        .permitAll()

                        // Every endpoint beginning
                        // with /api/admin/
                        // requires ROLE_ADMIN.
                        .requestMatchers("/api/admin/**")
                        .hasRole("ADMIN")

                        // Every remaining endpoint
                        // requires an authenticated user.
                        .anyRequest()
                        .authenticated()
                )

                // ---------------------------
                // H2 CONSOLE
                // ---------------------------
                //
                // Allows the H2 console
                // to be displayed inside a frame.
                //
                // Remove this in production.
                .headers(headers ->
                        headers.frameOptions(frame ->
                                frame.sameOrigin()
                        )
                )

                // ---------------------------
                // JWT FILTER
                // ---------------------------
                //
                // Execute our JWT filter BEFORE
                // Spring's username/password filter.
                //
                // Our filter:
                //
                // 1. Reads the JWT.
                // 2. Validates it.
                // 3. Loads the user.
                // 4. Stores authentication
                //    inside the SecurityContext.
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        // Build and return
        // the configured filter chain.
        return http.build();
    }

    @Bean
    // AuthenticationManager is responsible
    // for authenticating login requests.
    //
    // Example:
    //
    // authenticationManager.authenticate(...)
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config
    ) throws Exception {

        // Return the AuthenticationManager
        // created by Spring Security.
        return config.getAuthenticationManager();
    }

    @Bean
    // DaoAuthenticationProvider authenticates
    // users stored inside a database.
    //
    // It needs:
    //
    // - UserDetailsService
    // - PasswordEncoder
    public DaoAuthenticationProvider authenticationProvider(

            CustomUserDetailsService userDetailsService,

            PasswordEncoder passwordEncoder

    ) {

        // Create the provider.
        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(userDetailsService);

        // Tell Spring how passwords
        // are encoded and verified.
        provider.setPasswordEncoder(
                passwordEncoder
        );

        return provider;
    }

    @Bean
    // BCrypt password encoder.
    //
    // Used for:
    //
    // encode(...)
    //
    // and
    //
    // matches(...)
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    // Configure CORS.
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration =
                new CorsConfiguration();

        // Allow this frontend origin.
        configuration.setAllowedOrigins(
                List.of("http://localhost:3000")
        );

        // Allow these HTTP methods.
        configuration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "PATCH",
                        "DELETE",
                        "OPTIONS"
                )
        );

        // Allow these request headers.
        configuration.setAllowedHeaders(
                List.of(
                        "Authorization",
                        "Content-Type"
                )
        );

        // Allow cookies to be sent
        // in cross-origin requests.
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        // Apply this CORS configuration
        // to every endpoint.
        source.registerCorsConfiguration(
                "/**",
                configuration
        );

        return source;
    }
}
