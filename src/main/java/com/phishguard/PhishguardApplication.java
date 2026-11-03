package com.phishguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class PhishguardApplication {
    public static void main(String[] args) {
        SpringApplication.run(PhishguardApplication.class, args);
    }
}
