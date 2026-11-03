package com.phishguard.dto;

import java.util.List;
import java.util.Map;

public record UrlAnalyzeResponse(
        String url,
        String domain,
        String hostname,
        int score,
        String level,
        List<String> reasons,
        Map<String, Integer> breakdown,
        String source
) {}
