package dev.raul.escape.auth.dto;

import dev.raul.escape.user.AppUser;

public record RefreshTokenRotationResult(
        AppUser user,
        String refreshToken
) {
}