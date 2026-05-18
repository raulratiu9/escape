package dev.raul.escape.auth;

import dev.raul.escape.security.AuthenticatedUser;
import dev.raul.escape.user.AppUser;
import dev.raul.escape.user.AppUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthController(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
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

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest httpServletRequest) {
        String normalizedEmail = loginRequest.email()
                .trim()
                .toLowerCase();

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(normalizedEmail, loginRequest.password());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);

        httpServletRequest.getSession(true)
                .setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

        AuthenticatedUser authenticatedUser = (AuthenticatedUser) authentication.getPrincipal();

        return new AuthResponse(
                authenticatedUser.getUser()
                        .getId(),
                authenticatedUser.getUser()
                        .getEmail(),
                authenticatedUser.getUser()
                        .getDisplayName(),
                authenticatedUser.getUser()
                        .getRole()
                        .name());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
        }

        SecurityContextHolder.clearContext();
    }


}
