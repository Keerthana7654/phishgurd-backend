package com.phishguard.detection;

import com.phishguard.config.PhishguardProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Integrations with external threat-intelligence providers. Every check here
 * is OPTIONAL: if the corresponding API key is blank in application.yml
 * (env vars SAFE_BROWSING_API_KEY / VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY /
 * WHOIS_API_KEY), that check is skipped silently and contributes 0 to the
 * score. Any network error, timeout, or non-2xx response also fails open
 * (contributes 0, logs a warning) rather than breaking the whole analysis —
 * a third-party outage should never take PhishGuard itself down.
 */
@Service
public class ThreatIntelService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelService.class);

    @Autowired
    private PhishguardProperties properties;

    private final RestTemplate restTemplate = new RestTemplate();

    /** Safely coerces a JSON-deserialized numeric value (Integer, Double, etc., or null) to int. */
    private int toInt(Object value) {
        if (value instanceof Number n) return n.intValue();
        return 0;
    }

    public List<DetectionResult> runAll(String fullUrl, String hostname) {
        List<DetectionResult> results = new ArrayList<>();
        results.add(checkGoogleSafeBrowsing(fullUrl));
        results.add(checkVirusTotal(fullUrl));
        results.add(checkAbuseIpDb(hostname));
        results.add(checkWhoisDomainAge(hostname));
        return results;
    }

    public DetectionResult checkGoogleSafeBrowsing(String url) {
        var cfg = properties.getThreatIntel().getGoogleSafeBrowsing();
        if (!cfg.isConfigured()) return new DetectionResult("googleSafeBrowsing", 0, null);

        try {
            Map<String, Object> body = Map.of(
                    "client", Map.of("clientId", "phishguard", "clientVersion", "1.0.0"),
                    "threatInfo", Map.of(
                            "threatTypes", List.of("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"),
                            "platformTypes", List.of("ANY_PLATFORM"),
                            "threatEntryTypes", List.of("URL"),
                            "threatEntries", List.of(Map.of("url", url))
                    )
            );
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            String endpoint = cfg.getUrl() + "?key=" + cfg.getApiKey();

            var response = restTemplate.postForObject(endpoint, new HttpEntity<>(body, headers), Map.class);
            if (response != null && response.containsKey("matches")) {
                return new DetectionResult("googleSafeBrowsing", 40,
                        "Flagged by Google Safe Browsing as malware or social engineering.");
            }
            return new DetectionResult("googleSafeBrowsing", 0, null);
        } catch (RestClientException e) {
            log.warn("Google Safe Browsing check failed, skipping: {}", e.getMessage());
            return new DetectionResult("googleSafeBrowsing", 0, null);
        }
    }

    public DetectionResult checkVirusTotal(String url) {
        var cfg = properties.getThreatIntel().getVirustotal();
        if (!cfg.isConfigured()) return new DetectionResult("virustotal", 0, null);

        try {
            String urlId = java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(url.getBytes());
            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", cfg.getApiKey());

            var response = restTemplate.exchange(
                    cfg.getUrl() + "/" + urlId, HttpMethod.GET, new HttpEntity<>(headers), Map.class);

            Map<?, ?> data = (Map<?, ?>) response.getBody().get("data");
            Map<?, ?> attributes = (Map<?, ?>) data.get("attributes");
            Map<?, ?> stats = (Map<?, ?>) attributes.get("last_analysis_stats");
            int malicious = toInt(stats.get("malicious"));
            int suspicious = toInt(stats.get("suspicious"));

            if (malicious > 0) {
                return new DetectionResult("virustotal", 40,
                        malicious + " security vendor(s) flagged this URL as malicious on VirusTotal.");
            }
            if (suspicious > 0) {
                return new DetectionResult("virustotal", 15,
                        suspicious + " security vendor(s) flagged this URL as suspicious on VirusTotal.");
            }
            return new DetectionResult("virustotal", 0, null);
        } catch (Exception e) {
            log.warn("VirusTotal check failed or URL not yet indexed, skipping: {}", e.getMessage());
            return new DetectionResult("virustotal", 0, null);
        }
    }

    public DetectionResult checkAbuseIpDb(String hostname) {
        var cfg = properties.getThreatIntel().getAbuseipdb();
        if (!cfg.isConfigured()) return new DetectionResult("abuseipdb", 0, null);

        try {
            String ip = InetAddress.getByName(hostname).getHostAddress();

            HttpHeaders headers = new HttpHeaders();
            headers.set("Key", cfg.getApiKey());
            headers.set("Accept", "application/json");

            String endpoint = cfg.getUrl() + "?ipAddress=" + ip + "&maxAgeInDays=90";
            var response = restTemplate.exchange(endpoint, HttpMethod.GET, new HttpEntity<>(headers), Map.class);

            Map<?, ?> data = (Map<?, ?>) response.getBody().get("data");
            int abuseScore = toInt(data.get("abuseConfidenceScore"));

            if (abuseScore >= 50) {
                return new DetectionResult("abuseipdb", 25,
                        "Hosting IP has an AbuseIPDB confidence score of " + abuseScore + "%.");
            }
            return new DetectionResult("abuseipdb", 0, null);
        } catch (Exception e) {
            log.warn("AbuseIPDB check failed, skipping: {}", e.getMessage());
            return new DetectionResult("abuseipdb", 0, null);
        }
    }

    public DetectionResult checkWhoisDomainAge(String hostname) {
        var cfg = properties.getThreatIntel().getWhois();
        if (!cfg.isConfigured()) return new DetectionResult("whois", 0, null);

        try {
            String endpoint = cfg.getUrl() + "?apiKey=" + cfg.getApiKey()
                    + "&domainName=" + hostname + "&outputFormat=JSON";
            var response = restTemplate.getForObject(endpoint, Map.class);
            Map<?, ?> whoisRecord = (Map<?, ?>) response.get("WhoisRecord");
            String createdDateStr = (String) whoisRecord.get("createdDate");

            if (createdDateStr != null) {
                java.time.Instant created = java.time.Instant.parse(createdDateStr);
                long ageDays = java.time.Duration.between(created, java.time.Instant.now()).toDays();
                if (ageDays < 30) {
                    return new DetectionResult("whois", 20,
                            "Domain was registered only " + ageDays + " day(s) ago.");
                } else if (ageDays < 180) {
                    return new DetectionResult("whois", 8,
                            "Domain is relatively new (" + ageDays + " days old).");
                }
            }
            return new DetectionResult("whois", 0, null);
        } catch (Exception e) {
            log.warn("WHOIS check failed, skipping: {}", e.getMessage());
            return new DetectionResult("whois", 0, null);
        }
    }
}
