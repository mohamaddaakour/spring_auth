package com.springauth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
// Marks this class as a REST controller.
//
// Spring converts returned Java objects,
// such as Map, into JSON automatically.
@RequestMapping("/api/admin")
// Every endpoint inside this controller begins with:
//
// /api/admin
public class AdminController {

    @GetMapping("/dashboard")
    // Handles:
    //
    // GET /api/admin/dashboard
    @PreAuthorize("hasRole('ADMIN')")
    // Before this method runs, Spring Security checks
    // whether the authenticated user has:
    //
    // ROLE_ADMIN
    //
    // hasRole("ADMIN") automatically adds the "ROLE_" prefix.
    //
    // Therefore, it checks for:
    //
    // ROLE_ADMIN
    //
    // If the user is not authenticated:
    //
    // HTTP 401 Unauthorized
    //
    // If the user is authenticated but does not have ROLE_ADMIN:
    //
    // HTTP 403 Forbidden
    //
    // @PreAuthorize works because @EnableMethodSecurity
    // is enabled in SecurityConfig.
    public Map<String, String> dashboard() {

        // Create an immutable Map containing one key-value pair.
        //
        // Key:
        // "message"
        //
        // Value:
        // "Welcome, admin..."
        Map<String, String> response = Map.of(
                "message",
                "Welcome, admin. This endpoint required ROLE_ADMIN."
        );

        // Spring automatically converts this Map into JSON:
        //
        // {
        //   "message": "Welcome, admin. This endpoint required ROLE_ADMIN."
        // }
        return response;
    }
}