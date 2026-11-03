package com.phishguard.dto;

import java.util.List;
import java.util.Map;

public record StatsResponse(
        long totalScans,
        long safeCount,
        long moderateCount,
        long suspiciousCount,
        long dangerousCount,
        List<Map<String, Object>> mostTargetedDomains,
        List<ScanHistoryResponse> latestThreats
) {}
