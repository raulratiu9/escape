package dev.raul.escape.auth.dto;

public record JwtAuthResponse(String accessToken, String tokenType, long expiresIn) {
}
