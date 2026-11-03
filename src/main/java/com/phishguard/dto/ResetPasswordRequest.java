package com.phishguard.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank @Email String email,
        @NotBlank @Pattern(regexp = "\\d{6}", message = "The code must be 6 digits") String otp,
        @NotBlank @Size(min = 8, message = "Password must be at least 8 characters") String newPassword
) {}