package com.phishguard.dto;

public record AuthResponse(
        String accessToken,
        String tokenType,
        String email,
        String fullName,
        String role
) {
    public AuthResponse(String accessToken, String email, String fullName, String role) {
        this(accessToken, "Bearer", email, fullName, role);
    }
}
