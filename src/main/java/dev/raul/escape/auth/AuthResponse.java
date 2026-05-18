package dev.raul.escape.auth;

import java.util.UUID;


public record AuthResponse(
        UUID id,
        String email,
        String displayName,
        String role) {
}
