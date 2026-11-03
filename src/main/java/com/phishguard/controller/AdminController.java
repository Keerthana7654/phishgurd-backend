package com.phishguard.controller;

import com.phishguard.dto.ScanHistoryResponse;
import com.phishguard.dto.StatsResponse;
import com.phishguard.service.HistoryService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Everything under /api/admin/** requires ROLE_ADMIN — enforced centrally
 * in SecurityConfig, not repeated per-method here.
 */
@RestController
@RequestMapping("/api/admin")
@Tag(name = "Admin Dashboard")
public class AdminController {

    @Autowired
    private HistoryService historyService;

    @GetMapping("/stats")
    public ResponseEntity<StatsResponse> getStats() {
        return ResponseEntity.ok(historyService.getStats());
    }

    @GetMapping("/history")
    public ResponseEntity<Page<ScanHistoryResponse>> getAllHistory(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(historyService.getHistory(null, page, size));
    }
}
