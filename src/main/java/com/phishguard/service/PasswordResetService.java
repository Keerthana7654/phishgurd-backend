package com.phishguard.service;

import com.phishguard.dto.MessageResponse;
import com.phishguard.entity.PasswordResetOtp;
import com.phishguard.entity.User;
import com.phishguard.exception.ApiException;
import com.phishguard.repository.PasswordResetOtpRepository;
import com.phishguard.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;

/**
 * Three-step password reset: request a code -> verify it -> set a new password.
 *
 * Design choices worth knowing:
 *  - The code is stored only as a BCrypt hash.
 *  - requestOtp gives the SAME answer whether or not the email has an
 *    account, so the endpoint can't be used to discover who is registered.
 *  - Wrong guesses are counted; after maxAttempts the code is dead.
 *  - A code works once, then it's gone.
 *  - noRollbackFor = ApiException is deliberate: these methods throw
 *    ApiException for a wrong code AFTER incrementing the attempt counter.
 *    Without it Spring would roll the increment back and the attempt limit
 *    would never trigger.
 */
@Service
public class PasswordResetService {

    public static final String SENT_MESSAGE =
            "A 6-digit code has been sent to your registered email.";
    public static final String MAIL_NOT_EXIST =
            "Mail does not exist. Please Register";

    private static final SecureRandom RANDOM = new SecureRandom();

    @Autowired private UserRepository userRepository;
    @Autowired private PasswordResetOtpRepository otpRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private EmailService emailService;

    @Value("${phishguard.otp.expiry-minutes:10}")
    private int expiryMinutes;

    @Value("${phishguard.otp.max-attempts:5}")
    private int maxAttempts;

    @Value("${phishguard.otp.resend-cooldown-seconds:60}")
    private int cooldownSeconds;

    @Transactional(noRollbackFor = ApiException.class)
    public MessageResponse requestOtp(String rawEmail) throws Exception {
        String email = rawEmail.trim();
        MessageResponse generic = new MessageResponse(SENT_MESSAGE);

        MessageResponse mail_not_found = new MessageResponse(MAIL_NOT_EXIST);
        Optional<User> user = userRepository.findByEmail(email);
        if (user.isEmpty() || !user.get().isEnabled()) {
            return mail_not_found; // no account: say nothing different
        }

        Optional<PasswordResetOtp> latest = otpRepository.findTopByEmailOrderByCreatedAtDesc(email);
        if (latest.isPresent()
                && latest.get().getCreatedAt().plusSeconds(cooldownSeconds).isAfter(Instant.now())) {
            return generic; // asked again too soon: don't send another
        }

        otpRepository.deleteByEmail(email); // only the newest code is ever valid

        String otp = String.format("%06d", RANDOM.nextInt(1_000_000));
        PasswordResetOtp row = new PasswordResetOtp();
        row.setEmail(email);
        row.setOtpHash(passwordEncoder.encode(otp));
        row.setCreatedAt(Instant.now());
        row.setExpiresAt(Instant.now().plusSeconds(expiryMinutes * 60L));
        row.setAttempts(0);
        row.setUsed(false);
        otpRepository.save(row);

        try {
            emailService.sendOtp(email, otp, expiryMinutes);
        } catch (ApiException e) {
            otpRepository.delete(row); // nothing was delivered, so don't lock the user out of retrying
            throw e;
        }
        return generic;
    }

    @Transactional(noRollbackFor = ApiException.class)
    public MessageResponse verifyOtp(String rawEmail, String otp) {
        checkOtp(rawEmail.trim(), otp);
        return new MessageResponse("Code verified.");
    }

    @Transactional(noRollbackFor = ApiException.class)
    public MessageResponse resetPassword(String rawEmail, String otp, String newPassword) {
        String email = rawEmail.trim();
        PasswordResetOtp row = checkOtp(email, otp);

        User user = userRepository.findByEmail(email).orElseThrow(this::invalidCode);
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        row.setUsed(true);
        otpRepository.save(row);
        otpRepository.deleteByEmail(email);
        return new MessageResponse("Password updated. You can now sign in.");
    }

    private PasswordResetOtp checkOtp(String email, String otp) {
        PasswordResetOtp row = otpRepository.findTopByEmailOrderByCreatedAtDesc(email)
                .orElseThrow(this::invalidCode);

        if (row.isUsed() || row.getExpiresAt().isBefore(Instant.now())) {
            throw invalidCode();
        }
        if (row.getAttempts() >= maxAttempts) {
            throw new ApiException("Too many incorrect attempts. Please request a new code.",
                    HttpStatus.TOO_MANY_REQUESTS);
        }
        if (!passwordEncoder.matches(otp, row.getOtpHash())) {
            row.setAttempts(row.getAttempts() + 1);
            otpRepository.save(row);
            int left = maxAttempts - row.getAttempts();
            throw new ApiException(
                    left > 0 ? "Incorrect code. " + left + " attempt(s) left."
                             : "Too many incorrect attempts. Please request a new code.",
                    left > 0 ? HttpStatus.BAD_REQUEST : HttpStatus.TOO_MANY_REQUESTS);
        }
        return row;
    }

    private ApiException invalidCode() {
        return new ApiException("That code is invalid or has expired.", HttpStatus.BAD_REQUEST);
    }
}