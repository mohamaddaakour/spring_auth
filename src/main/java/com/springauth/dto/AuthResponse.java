package com.springauth.dto;

import java.util.Set;

public record AuthResponse(
        String accessToken,
        String email,
        Set<String> roles
) {}