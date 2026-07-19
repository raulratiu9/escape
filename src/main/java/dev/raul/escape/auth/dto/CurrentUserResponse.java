package dev.raul.escape.auth.dto;

import java.util.UUID;

public record CurrentUserResponse(
        UUID id,
        String email,
        String displayName,
        String role,
        String authProvider
) {
}