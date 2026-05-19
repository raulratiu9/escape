package dev.raul.escape.auth;

import dev.raul.escape.user.AppUser;

public record RefreshTokenRotationResult(
        AppUser user,
        String refreshToken
) {
}