package com.springauth.service;

import com.springauth.dto.AuthResponse;
import com.springauth.dto.LoginRequest;
import com.springauth.dto.RegisterRequest;
import com.springauth.entity.RefreshToken;
import com.springauth.entity.User;
import com.springauth.exception.EmailAlreadyExistsException;
import com.springauth.exception.TokenRefreshException;
import com.springauth.repository.RefreshTokenRepository;
import com.springauth.repository.UserRepository;
import com.springauth.security.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String REFRESH_COOKIE = "refreshToken";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Value("${app.jwt.refresh-token-expiration-days}")
    private long refreshTokenExpirationDays;

    @Value("${app.cookie.secure:false}")
    private boolean secureCookie;

    @Transactional
    public AuthResponse register(RegisterRequest request, HttpServletResponse response) {
        String email = normalizeEmail(request.email());
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException(email);
        }

        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(request.password()))
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .build();

        userRepository.save(user);
        return issueTokens(user, response);
    }

    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletResponse response) {
        String email = normalizeEmail(request.email());
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.password()));
        User user = (User) authentication.getPrincipal();

        refreshTokenRepository.revokeAllByUser(user);
        return issueTokens(user, response);
    }

    @Transactional
    public AuthResponse refresh(String refreshToken, HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new TokenRefreshException("Refresh token is missing");
        }

        RefreshToken storedToken = refreshTokenRepository.findByTokenHash(hash(refreshToken))
                .orElseThrow(() -> new TokenRefreshException("Refresh token is invalid"));

        if (storedToken.isRevoked() || storedToken.getExpiryDate().isBefore(Instant.now())) {
            storedToken.setRevoked(true);
            refreshTokenRepository.save(storedToken);
            clearRefreshCookie(response);
            throw new TokenRefreshException("Refresh token is expired or revoked");
        }

        User user = storedToken.getUser();
        if (!user.isEnabled()) {
            throw new TokenRefreshException("User account is disabled");
        }

        storedToken.setRevoked(true);
        return issueTokens(user, response);
    }

    @Transactional
    public void logout(String refreshToken, HttpServletResponse response) {
        if (refreshToken != null && !refreshToken.isBlank()) {
            refreshTokenRepository.findByTokenHash(hash(refreshToken))
                    .ifPresent(token -> token.setRevoked(true));
        }
        clearRefreshCookie(response);
    }

    private AuthResponse issueTokens(User user, HttpServletResponse response) {
        String rawRefreshToken = createRefreshToken();
        Instant expiryDate = Instant.now().plus(Duration.ofDays(refreshTokenExpirationDays));

        refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash(hash(rawRefreshToken))
                .user(user)
                .expiryDate(expiryDate)
                .build());

        addRefreshCookie(response, rawRefreshToken);
        return new AuthResponse(jwtService.generateAccessToken(user), user.getEmail(), user.getRoles());
    }

    private String createRefreshToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private void addRefreshCookie(HttpServletResponse response, String refreshToken) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, refreshToken)
                .httpOnly(true)
                .secure(secureCookie)
                .sameSite("Strict")
                .path("/api/auth")
                .maxAge(Duration.ofDays(refreshTokenExpirationDays))
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, "")
                .httpOnly(true)
                .secure(secureCookie)
                .sameSite("Strict")
                .path("/api/auth")
                .maxAge(Duration.ZERO)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
