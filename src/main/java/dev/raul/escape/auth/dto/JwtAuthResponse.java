package dev.raul.escape.auth.dto;

public record JwtAuthResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {
}
