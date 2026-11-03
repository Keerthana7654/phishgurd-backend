package com.phishguard.config;

import com.phishguard.entity.Role;
import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Creates a default admin account on first boot so the admin dashboard is
 * usable immediately without a manual SQL insert. Override the credentials
 * via env vars in any real deployment — the defaults are for local dev only.
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    @Value("${PHISHGUARD_ADMIN_EMAIL:}")
    private String adminEmail;

    @Value("${PHISHGUARD_ADMIN_PASSWORD:}")
    private String adminPassword;

    @Override
    public void run(String... args) {
        if (userRepository.findByEmail(adminEmail).isEmpty()) {
            User admin = User.builder()
                    .email(adminEmail)
                    .passwordHash(passwordEncoder.encode(adminPassword))
                    .fullName("PhishGuard Admin")
                    .role(Role.ROLE_ADMIN)
                    .enabled(true)
                    .build();
            userRepository.save(admin);
            // log.info("Seeded default admin account: {} (change the password after first login!)", adminEmail);
            // log.info(".passwordHash(passwordEncoder.encode(adminPassword)) {}",passwordEncoder.encode("Admin@123"));
        }
    }
}
