package com.phishguard.exception;

import java.time.Instant;
import java.util.Map;

public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        Object details
) {
    public static ErrorResponse of(int status, String error, Object details) {
        return new ErrorResponse(Instant.now(), status, error, details);
    }

    public static ErrorResponse of(int status, String error) {
        return of(status, error, Map.of());
    }
}
