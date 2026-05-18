package dev.raul.escape.security;

import dev.raul.escape.user.AppUser;
import dev.raul.escape.user.AppUserRepository;
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

        return new AuthenticatedUser(user);
    }
}
