package com.phishguard.service;

import com.phishguard.config.PhishguardProperties;
import com.phishguard.detection.DetectionResult;
import com.phishguard.detection.HeuristicDetectors;
import com.phishguard.detection.RedirectResolverService;
import com.phishguard.detection.ThreatIntelService;
import com.phishguard.dto.UrlAnalyzeResponse;
import com.phishguard.exception.ApiException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class UrlAnalysisService {

    @Autowired
    private HeuristicDetectors detectors;

    @Autowired
    private ThreatIntelService threatIntelService;

    @Autowired
    private RedirectResolverService redirectResolverService;

    @Autowired
    private PhishguardProperties properties;

    public UrlAnalyzeResponse analyze(String rawUrl) {
        URI uri;
        try {
            uri = new URI(rawUrl);
            if (uri.getHost() == null) throw new URISyntaxException(rawUrl, "missing host");
        } catch (URISyntaxException e) {
            throw new ApiException("Invalid URL: " + rawUrl, HttpStatus.BAD_REQUEST);
        }

        String originalHostname = uri.getHost().toLowerCase();

        // If this is a known shortener (bit.ly, tinyurl.com, etc.), resolve
        // the real destination server-side and analyze THAT — otherwise a
        // shortened phishing link only gets the weak "this is a shortener"
        // signal (10 points, stays "safe" on its own) instead of the full
        // analysis its actual target deserves. See RedirectResolverService
        // for why this is safe to do server-side but not client-side, and
        // its SSRF protections.
        URI analysisUri = uri;
        boolean redirectResolved = false;
        if (redirectResolverService.isShortener(originalHostname)) {
            String resolvedUrl = redirectResolverService.resolveFinalUrl(rawUrl);
            if (!resolvedUrl.equals(rawUrl)) {
                try {
                    URI resolvedUri = new URI(resolvedUrl);
                    if (resolvedUri.getHost() != null) {
                        analysisUri = resolvedUri;
                        redirectResolved = true;
                    }
                } catch (URISyntaxException ignored) {
                    // Malformed Location header from the shortener — fall back
                    // to analyzing the original shortened URL itself below.
                }
            }
        }

        String hostname = analysisUri.getHost().toLowerCase();
        String path = (analysisUri.getRawPath() != null ? analysisUri.getRawPath() : "")
                + (analysisUri.getRawQuery() != null ? "?" + analysisUri.getRawQuery() : "");
        String domain = detectors.registrableDomain(hostname);

        List<DetectionResult> results = new ArrayList<>();
        results.add(detectors.checkProtocol(analysisUri));
        results.add(detectors.checkIpLiteral(hostname));
        results.add(detectors.checkPunycode(hostname));
        results.add(detectors.checkTyposquat(hostname));
        results.add(detectors.checkSubdomainImpersonation(hostname));
        results.add(detectors.checkSubdomainDepth(hostname));
        results.add(detectors.checkKeywords(hostname, path));
        results.add(detectors.checkEntropy(hostname));
        // Always evaluated against the ORIGINAL host, so "shortener
        // detected" still shows up even after resolving to the real target.
        results.add(detectors.checkShortener(originalHostname));
        results.add(detectors.checkLegacyDomain(hostname));
        results.add(detectors.checkIndianBankName(hostname));

        // External, API-key-gated checks run against the RESOLVED
        // destination when we have one — that's the URL that actually
        // matters for Safe Browsing / VirusTotal / AbuseIPDB / WHOIS.
        String urlForThreatIntel = redirectResolved ? analysisUri.toString() : rawUrl;
        results.addAll(threatIntelService.runAll(urlForThreatIntel, hostname));

        int totalScore = 0;
        List<String> reasons = new ArrayList<>();
        Map<String, Integer> breakdown = new LinkedHashMap<>();

        for (DetectionResult r : results) {
            breakdown.put(r.checkName(), r.scoreContribution());
            totalScore += r.scoreContribution();
            if (r.fired()) reasons.add(r.reason());
        }

        if (redirectResolved) {
            reasons.add("Shortened link resolves to " + domain + " — analysis below reflects that real destination.");
        }

        // Combo bonus: a near-miss/embedded brand name PLUS a login/security
        // keyword together (e.g. "paypaI-secure-login.tk") is a much stronger
        // phishing signal than either alone — the single most common
        // real-world fake banking/payment page pattern.
        int typosquatScore = breakdown.getOrDefault("typosquat", 0);
        int keywordScore = breakdown.getOrDefault("keywords", 0);
        if (typosquatScore > 0 && keywordScore > 0) {
            int comboScore = 20;
            breakdown.put("brandKeywordCombo", comboScore);
            totalScore += comboScore;
            reasons.add("Combines a brand-name look-alike with login/security keywords — a classic fake login page pattern.");
        } else {
            breakdown.put("brandKeywordCombo", 0);
        }

        totalScore = Math.max(0, Math.min(100, totalScore));

        if (reasons.isEmpty()) {
            reasons.add("No known phishing indicators detected.");
        }

        String level;
        if (totalScore <= 20) level = "safe";
        else if (totalScore <= 50) level = "moderate";
        else if (totalScore <= 75) level = "suspicious";
        else level = "dangerous";

        return new UrlAnalyzeResponse(rawUrl, domain, hostname, totalScore, level, reasons, breakdown, "backend");
    }
}
