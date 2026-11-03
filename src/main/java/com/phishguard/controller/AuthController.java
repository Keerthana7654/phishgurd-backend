package com.phishguard.controller;

import com.phishguard.dto.AuthResponse;
import com.phishguard.dto.ForgotPasswordRequest;
import com.phishguard.dto.LoginRequest;
import com.phishguard.dto.MessageResponse;
import com.phishguard.dto.RegisterRequest;
import com.phishguard.dto.ResetPasswordRequest;
import com.phishguard.dto.VerifyOtpRequest;
import com.phishguard.service.AuthService;
import com.phishguard.service.PasswordResetService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private PasswordResetService passwordResetService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    // ---- Forgot password (all public — covered by /api/auth/** in SecurityConfig) ----

    @PostMapping("/forgot-password")
    public ResponseEntity<MessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) throws Exception {
        return ResponseEntity.ok(passwordResetService.requestOtp(request.email()));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<MessageResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        return ResponseEntity.ok(passwordResetService.verifyOtp(request.email(), request.otp()));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<MessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(passwordResetService.resetPassword(
                request.email(), request.otp(), request.newPassword()));
    }
}