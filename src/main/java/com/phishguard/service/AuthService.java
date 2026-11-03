package com.phishguard.service;

import com.phishguard.dto.AuthResponse;
import com.phishguard.dto.LoginRequest;
import com.phishguard.dto.RegisterRequest;
import com.phishguard.entity.Role;
import com.phishguard.entity.User;
import com.phishguard.exception.ApiException;
import com.phishguard.repository.UserRepository;
import com.phishguard.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new ApiException("An account with this email already exists.", HttpStatus.CONFLICT);
        }

        User user = User.builder()
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .fullName(request.fullName())
                .role(Role.ROLE_USER)
                .enabled(true)
                .build();

        userRepository.save(user);

        String token = jwtUtil.generateAccessToken(user.getEmail(), user.getRole().name());
        return new AuthResponse(token, user.getEmail(), user.getFullName(), user.getRole().name());
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password()));

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new ApiException("Invalid email or password", HttpStatus.UNAUTHORIZED));

        String token = jwtUtil.generateAccessToken(user.getEmail(), user.getRole().name());
        return new AuthResponse(token, user.getEmail(), user.getFullName(), user.getRole().name());
    }
}
