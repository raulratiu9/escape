package dev.raul.escape.auth;

import dev.raul.escape.auth.dto.JwtAuthResponse;
import dev.raul.escape.security.AuthenticatedUser;
import dev.raul.escape.user.AppUser;
import dev.raul.escape.user.AppUserRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;

    public AuthController(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtEncoder jwtEncoder) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
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
        long expiresIn = 900;
        Instant now = Instant.now();

        JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256)
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(
                        jwsHeader,
                        JwtClaimsSet.builder()
                                .issuer("escape-api")
                                .issuedAt(now)
                                .expiresAt(now.plusSeconds(expiresIn))
                                .subject(authenticatedUser.getUser()
                                        .getId()
                                        .toString())
                                .claim("email", authenticatedUser.getUser()
                                        .getEmail())
                                .claim("role", authenticatedUser.getUser()
                                        .getRole()
                                        .name())
                                .build()
                ))
                .getTokenValue();

        return new JwtAuthResponse(token, "Bearer", expiresIn);
    }

//    @PostMapping("/logout")
//    @ResponseStatus(HttpStatus.NO_CONTENT)
//    public void logout(HttpServletRequest request, HttpServletResponse response) {
//        HttpSession session = request.getSession(false);
//
//        if (session != null) {
//            session.invalidate();
//        }
//
//        SecurityContextHolder.clearContext();
//    }


}
