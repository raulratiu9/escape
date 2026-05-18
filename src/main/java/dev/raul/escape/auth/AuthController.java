package dev.raul.escape.auth;

import dev.raul.escape.security.AuthenticatedUser;
import dev.raul.escape.user.AppUser;
import dev.raul.escape.user.AppUserRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/me")
    public CurrentUserResponse currentUser(@AuthenticationPrincipal AuthenticatedUser authenticatedUser) {

        return new CurrentUserResponse(
                authenticatedUser.getUser()
                        .getId(),
                authenticatedUser.getUser()
                        .getEmail(),
                authenticatedUser.getUser()
                        .getDisplayName(),
                authenticatedUser.getUser()
                        .getRole()
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


}
