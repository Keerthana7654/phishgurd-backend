package com.phishguard.controller;

import com.phishguard.dto.UrlAnalyzeRequest;
import com.phishguard.dto.UrlAnalyzeResponse;
import com.phishguard.service.HistoryService;
import com.phishguard.service.UrlAnalysisService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Public endpoint (no auth required) — this is exactly what the Chrome
 * extension's background.js calls at POST {backendUrl}/api/url/analyze.
 * If the request carries a valid JWT (a logged-in user in the web dashboard),
 * the scan is attributed to that user; otherwise it's recorded anonymously
 * so the extension works standalone with no account.
 */
@RestController
@RequestMapping("/api/url")
@Tag(name = "URL Analysis")
public class UrlAnalysisController {

    @Autowired private UrlAnalysisService urlAnalysisService;
    @Autowired private HistoryService historyService;

    @PostMapping("/analyze")
    public ResponseEntity<UrlAnalyzeResponse> analyze(@Valid @RequestBody UrlAnalyzeRequest request,
                                                        Authentication authentication) {
        UrlAnalyzeResponse result = urlAnalysisService.analyze(request.url());

        String userEmail = authentication != null ? authentication.getName() : null;
        boolean blocked = "dangerous".equals(result.level());
        historyService.recordScan(result, userEmail, blocked);

        return ResponseEntity.ok(result);
    }
}
