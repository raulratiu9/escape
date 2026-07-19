package dev.raul.escape.auth.controller;

import dev.raul.escape.auth.dto.*;
import dev.raul.escape.auth.exception.EmailAlreadyRegisteredException;
import dev.raul.escape.auth.exception.OAuth2EmailMissingException;
import dev.raul.escape.auth.service.JwtService;
import dev.raul.escape.auth.service.RefreshTokenService;
import dev.raul.escape.security.AuthenticatedUser;
import dev.raul.escape.security.JpaUserDetailsService;
import dev.raul.escape.user.AppUser;
import dev.raul.escape.user.AppUserRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final long ACCESS_TOKEN_EXPIRES_IN = 900;
    private final AppUserRepository appUserRepository;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JpaUserDetailsService jpaUserDetailsService;

    public AuthController(AppUserRepository appUserRepository, RefreshTokenService refreshTokenService, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtService jwtService, JpaUserDetailsService jpaUserDetailsService) {
        this.appUserRepository = appUserRepository;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.jpaUserDetailsService = jpaUserDetailsService;
    }

    @GetMapping("/me")
    public CurrentUserResponse currentUser(JwtAuthenticationToken authentication) {

        String userId = authentication.getToken()
                .getSubject();

        AppUser user = appUserRepository.findById(UUID.fromString(userId))
                .orElseThrow();

        return new CurrentUserResponse(
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                user.getRole()
                        .name(),
                user.getAuthProvider()
                        .name()
        );
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public AuthResponse register(@Valid @RequestBody RegisterRequest registerRequest) {
        String normalizedEmail = registerRequest.email()
                .trim()
                .toLowerCase();

        if (appUserRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyRegisteredException(normalizedEmail);
        }

        String passwordHash = passwordEncoder.encode(registerRequest.password());

        AppUser user = new AppUser(normalizedEmail, passwordHash, registerRequest.displayName()
                .trim());

        AppUser savedUser = appUserRepository.save(user);

        return new AuthResponse(savedUser.getId(), savedUser.getEmail(), savedUser.getDisplayName(), savedUser.getRole()
                .name());
    }

    @PostMapping("/login")
    public JwtAuthResponse login(@Valid @RequestBody LoginRequest loginRequest) {
        String normalizedEmail = loginRequest.email()
                .trim()
                .toLowerCase();

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(normalizedEmail, loginRequest.password());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        AuthenticatedUser authenticatedUser = (AuthenticatedUser) authentication.getPrincipal();
        String token = jwtService.generateAccessToken(authenticatedUser.getUser());
        String refreshToken = refreshTokenService.createRefreshToken(authenticatedUser.getUser());

        return new JwtAuthResponse(token, refreshToken, "Bearer", ACCESS_TOKEN_EXPIRES_IN);
    }

    @PostMapping("/refresh")
    public JwtAuthResponse refresh(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        RefreshTokenRotationResult rotationResult =
                refreshTokenService.rotateRefreshToken(refreshTokenRequest.refreshToken());

        AppUser user = rotationResult.user();

        String accessToken = jwtService.generateAccessToken(user);

        return new JwtAuthResponse(
                accessToken,
                rotationResult.refreshToken(),
                "Bearer",
                ACCESS_TOKEN_EXPIRES_IN
        );
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody LogoutRequest logoutRequest) {
        refreshTokenService.revokeRefreshToken(logoutRequest.refreshToken());
    }

    @GetMapping("/oauth2/success")
    public JwtAuthResponse oauth2Success(@AuthenticationPrincipal OAuth2User oauth2User) {
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        if (email == null || email.isBlank()) {
            throw new OAuth2EmailMissingException();
        }

        if (name == null || name.isBlank()) {
            name = email;
        }

        AppUser user = jpaUserDetailsService.findOrCreateGoogleUser(email, name);
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user);

        return new JwtAuthResponse(
                accessToken,
                refreshToken,
                "Bearer",
                ACCESS_TOKEN_EXPIRES_IN
        );
    }


}
