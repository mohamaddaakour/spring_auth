package com.springauth.security;

import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

// Authorization error handler per example a user try to
// use /admin endpoint
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    // Jackson object used to convert Java objects
    // into JSON.
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                        AccessDeniedException accessDeniedException) throws IOException {
        
        // Set HTTP status code.
        // 403 = Authenticated but not allowed.
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        // Tell the client the response body is JSON.
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = Map.of(
                "timestamp", Instant.now().toString(),
                "status", 403,
                "error", "Forbidden",
                "message", "You do not have permission to access this resource",
                "path", request.getRequestURI()
        );

        // Convert the Map into JSON
        // and write it directly into the HTTP response.
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}