package com.phishguard.dto;

import java.time.Instant;
import java.util.List;

public record ScanHistoryResponse(
        Long id,
        String url,
        String domain,
        int score,
        String level,
        List<String> reasons,
        boolean blocked,
        Instant createdAt,
        // Email of the logged-in user who scanned it, or null for anonymous
        // scans — which is what the Chrome extension and Android app produce,
        // since neither requires login.
        String scannedBy
) {}
