package com.phishguard.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "scan_history", indexes = {
        @Index(name = "idx_scan_user", columnList = "user_id"),
        @Index(name = "idx_scan_domain", columnList = "domain"),
        @Index(name = "idx_scan_created", columnList = "createdAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false, length = 2048)
    private String url;

    @Column(nullable = false)
    private String domain;

    @Column(nullable = false)
    private int score;

    @Column(nullable = false)
    private String level;

    @Column(nullable = false, length = 2000)
    private String reasons;

    @Builder.Default
    private boolean blocked = false;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
    }
}
