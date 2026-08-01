package com.springauth.dto;

import java.util.Set;

public record MeResponse(
        Long id,
        String email,
        Set<String> roles,
        boolean enabled
) {}
