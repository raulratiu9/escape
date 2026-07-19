package dev.raul.escape.security;

import dev.raul.escape.auth.exception.EmailAlreadyRegisteredWithLocalLoginException;
import dev.raul.escape.user.AppUser;
import dev.raul.escape.user.AppUserRepository;
import dev.raul.escape.user.AuthProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JpaUserDetailsService implements UserDetailsService {
    public final AppUserRepository appUserRepository;

    public JpaUserDetailsService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = appUserRepository.findByEmail(username
                        .toLowerCase())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if (user.getAuthProvider() != AuthProvider.LOCAL || user.getPasswordHash() == null) {
            throw new UsernameNotFoundException("User has no local password");
        }
        
        return new AuthenticatedUser(user);
    }

    public AppUser findOrCreateGoogleUser(String email, String displayName) {
        String normalizedEmail = email.trim()
                .toLowerCase();

        return appUserRepository.findByEmail(normalizedEmail)
                .map(existingUser -> {
                    if (existingUser.getAuthProvider() == AuthProvider.LOCAL) {
                        throw new EmailAlreadyRegisteredWithLocalLoginException(normalizedEmail);
                    }

                    return existingUser;
                })
                .orElseGet(() -> {
                    AppUser user = new AppUser(
                            normalizedEmail,
                            null,
                            displayName,
                            AuthProvider.GOOGLE
                    );

                    return appUserRepository.save(user);
                });
    }
}
