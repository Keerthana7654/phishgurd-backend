package com.phishguard.service;

import com.phishguard.exception.ApiException;

import java.io.UnsupportedEncodingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.mail.MailException;
// import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.MimeMessageHelper;


@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    // Only present when spring.mail.host is configured.
    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Value("${spring.mail.username:}")
    private String from;
    @Value("${spring.mail.from-name:PhishGuard}")
    private String fromName;

    // Dev-only escape hatch: print the code in the server log instead of
    // emailing it. Off by default — a code in a log file is a code anyone
    // with log access can use.
    @Value("${phishguard.otp.log-to-console:false}")
    private boolean logOtpToConsole;

    public void sendOtp(String to, String otp, int expiryMinutes) throws Exception {
        if (logOtpToConsole) {
            log.warn("DEV MODE (phishguard.otp.log-to-console=true): reset code for {} is {}", to, otp);
            return;
        }
        if (mailSender == null || from == null || from.isBlank()) {
            log.error("Password-reset email not sent: set MAIL_USERNAME and MAIL_PASSWORD (see README).");
            throw new ApiException(
                    "Email sending isn't configured on the server yet.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setFrom(from,fromName);
        helper.setTo(to);
        helper.setSubject("Your PhishGuard password reset code");
        helper.setText(
                "Your PhishGuard password reset code is:\n\n"
                        + "    " + otp + "\n\n"
                        + "It expires in " + expiryMinutes + " minutes. "
                        + "If you didn't ask to reset your password, ignore this email — "
                        + "your password has not been changed.\n\n"
                        + "Never share this code with anyone.");
        try {
            mailSender.send(message);
        } catch (MailException e) {
            log.error("Could not send password-reset email to {}: {}", to, e.getMessage());
            throw new ApiException(
                    "We couldn't send the email. Please try again in a moment.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}