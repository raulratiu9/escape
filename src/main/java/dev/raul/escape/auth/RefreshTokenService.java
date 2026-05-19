package dev.raul.escape.auth;

import dev.raul.escape.user.AppUser;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
public class RefreshTokenService {

    private static final int REFRESH_TOKEN_BYTES = 64;
    private static final long REFRESH_TOKEN_TTL_SECONDS = 60L * 60 * 24 * 30;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        secureRandom.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    private String hashToken(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder()
                    .encodeToString(digest);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not hash refresh token", exception);
        }
    }

    @Transactional
    public String createRefreshToken(AppUser user) {
        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = new RefreshToken(
                user,
                tokenHash,
                Instant.now()
                        .plusSeconds(REFRESH_TOKEN_TTL_SECONDS)
        );

        refreshTokenRepository.save(refreshToken);

        return rawToken;
    }

    public RefreshToken validateRefreshToken(String rawToken) {
        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (!refreshToken.isActive()) {
            throw new InvalidRefreshTokenException("Refresh token is expired or revoked");
        }

        return refreshToken;
    }

    @Transactional
    public RefreshTokenRotationResult rotateRefreshToken(String rawToken) {
        RefreshToken existingRefreshToken = validateRefreshToken(rawToken);

        existingRefreshToken.revoke();

        String newRawToken = createRefreshToken(existingRefreshToken.getUser());

        return new RefreshTokenRotationResult(
                existingRefreshToken.getUser(),
                newRawToken
        );
    }

    @Transactional
    public void revokeRefreshToken(String rawToken) {
        RefreshToken refreshToken = validateRefreshToken(rawToken);
        refreshToken.revoke();
    }

}
