package com.phishguard.repository;

import com.phishguard.entity.PasswordResetOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, Long> {
    Optional<PasswordResetOtp> findTopByEmailOrderByCreatedAtDesc(String email);
    void deleteByEmail(String email);
}