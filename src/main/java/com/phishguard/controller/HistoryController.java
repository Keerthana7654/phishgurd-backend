package com.phishguard.controller;

import com.phishguard.dto.ScanHistoryResponse;
import com.phishguard.service.HistoryService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/history")
@Tag(name = "Scan History")
public class HistoryController {

    @Autowired
    private HistoryService historyService;

    /**
     * Returns the authenticated user's own scan history, paginated.
     * Requires a valid JWT (set by SecurityConfig — anyRequest().authenticated()
     * covers everything under /api/** except /api/auth/** and /api/url/analyze).
     */
    @GetMapping
    public ResponseEntity<Page<ScanHistoryResponse>> getMyHistory(
            Authentication authentication,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        String email = authentication.getName();
        return ResponseEntity.ok(historyService.getHistory(email, page, size));
    }
}
