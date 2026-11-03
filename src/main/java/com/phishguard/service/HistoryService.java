package com.phishguard.service;

import com.phishguard.dto.ScanHistoryResponse;
import com.phishguard.dto.StatsResponse;
import com.phishguard.dto.UrlAnalyzeResponse;
import com.phishguard.entity.ScanHistory;
import com.phishguard.entity.User;
import com.phishguard.repository.ScanHistoryRepository;
import com.phishguard.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class HistoryService {

    @Autowired private ScanHistoryRepository scanHistoryRepository;
    @Autowired private UserRepository userRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public void recordScan(UrlAnalyzeResponse analysis, String userEmail, boolean blocked) {
        User user = null;
        if (userEmail != null) {
            user = userRepository.findByEmail(userEmail).orElse(null);
        }

        String reasonsJson;
        try {
            reasonsJson = objectMapper.writeValueAsString(analysis.reasons());
        } catch (Exception e) {
            reasonsJson = "[]";
        }

        ScanHistory entry = ScanHistory.builder()
                .user(user)
                .url(truncate(analysis.url(), 2048))
                .domain(analysis.domain())
                .score(analysis.score())
                .level(analysis.level())
                .reasons(truncate(reasonsJson, 2000))
                .blocked(blocked)
                .build();

        scanHistoryRepository.save(entry);
    }

    // @Transactional(readOnly) matters here: ScanHistory.user is LAZY and
    // open-in-view is off, so reading the scanner's email while mapping to
    // the DTO would throw LazyInitializationException outside a session.
    @Transactional(readOnly = true)
    public Page<ScanHistoryResponse> getHistory(String userEmail, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));

        Page<ScanHistory> results;
        if (userEmail != null) {
            User user = userRepository.findByEmail(userEmail).orElse(null);
            results = user != null
                    ? scanHistoryRepository.findByUserOrderByCreatedAtDesc(user, pageable)
                    : Page.empty(pageable);
        } else {
            results = scanHistoryRepository.findAllByOrderByCreatedAtDesc(pageable);
        }

        return results.map(this::toResponse);
    }

    @Transactional(readOnly = true)
    public StatsResponse getStats() {
        long total = scanHistoryRepository.count();
        long safe = scanHistoryRepository.countByLevel("safe");
        long moderate = scanHistoryRepository.countByLevel("moderate");
        long suspicious = scanHistoryRepository.countByLevel("suspicious");
        long dangerous = scanHistoryRepository.countByLevel("dangerous");

        List<Map<String, Object>> mostTargeted = scanHistoryRepository
                .findMostTargetedDomains(PageRequest.of(0, 10))
                .stream()
                .map(row -> Map.of("domain", row[0], "count", row[1]))
                .toList();

        List<ScanHistoryResponse> latestThreats = scanHistoryRepository
                .findTop10ByLevelOrderByCreatedAtDesc("dangerous")
                .stream()
                .map(this::toResponse)
                .toList();

        return new StatsResponse(total, safe, moderate, suspicious, dangerous, mostTargeted, latestThreats);
    }

    private ScanHistoryResponse toResponse(ScanHistory sh) {
        List<String> reasons;
        try {
            reasons = objectMapper.readValue(sh.getReasons(), List.class);
        } catch (Exception e) {
            reasons = List.of();
        }
        return new ScanHistoryResponse(
                sh.getId(), sh.getUrl(), sh.getDomain(), sh.getScore(), sh.getLevel(),
                reasons, sh.isBlocked(), sh.getCreatedAt(),
                sh.getUser() != null ? sh.getUser().getEmail() : null);
    }

    private String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) : s;
    }
}
