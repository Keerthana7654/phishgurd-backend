package com.phishguard.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "phishguard")
public class PhishguardProperties {

    private Jwt jwt = new Jwt();
    private Cors cors = new Cors();
    private Scoring scoring = new Scoring();
    private ThreatIntel threatIntel = new ThreatIntel();

    public Jwt getJwt() { return jwt; }
    public void setJwt(Jwt jwt) { this.jwt = jwt; }
    public Cors getCors() { return cors; }
    public void setCors(Cors cors) { this.cors = cors; }
    public Scoring getScoring() { return scoring; }
    public void setScoring(Scoring scoring) { this.scoring = scoring; }
    public ThreatIntel getThreatIntel() { return threatIntel; }
    public void setThreatIntel(ThreatIntel threatIntel) { this.threatIntel = threatIntel; }

    public static class Jwt {
        private String secret;
        private long accessTokenExpiryMs;
        private long refreshTokenExpiryMs;
        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }
        public long getAccessTokenExpiryMs() { return accessTokenExpiryMs; }
        public void setAccessTokenExpiryMs(long v) { this.accessTokenExpiryMs = v; }
        public long getRefreshTokenExpiryMs() { return refreshTokenExpiryMs; }
        public void setRefreshTokenExpiryMs(long v) { this.refreshTokenExpiryMs = v; }
    }

    public static class Cors {
        private String allowedOrigins;
        public String getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(String allowedOrigins) { this.allowedOrigins = allowedOrigins; }
    }

    public static class Scoring {
        private int warnThreshold;
        private int blockThreshold;
        public int getWarnThreshold() { return warnThreshold; }
        public void setWarnThreshold(int v) { this.warnThreshold = v; }
        public int getBlockThreshold() { return blockThreshold; }
        public void setBlockThreshold(int v) { this.blockThreshold = v; }
    }

    public static class ThreatIntel {
        private ApiEndpoint googleSafeBrowsing = new ApiEndpoint();
        private ApiEndpoint virustotal = new ApiEndpoint();
        private ApiEndpoint abuseipdb = new ApiEndpoint();
        private ApiEndpoint whois = new ApiEndpoint();
        public ApiEndpoint getGoogleSafeBrowsing() { return googleSafeBrowsing; }
        public void setGoogleSafeBrowsing(ApiEndpoint v) { this.googleSafeBrowsing = v; }
        public ApiEndpoint getVirustotal() { return virustotal; }
        public void setVirustotal(ApiEndpoint v) { this.virustotal = v; }
        public ApiEndpoint getAbuseipdb() { return abuseipdb; }
        public void setAbuseipdb(ApiEndpoint v) { this.abuseipdb = v; }
        public ApiEndpoint getWhois() { return whois; }
        public void setWhois(ApiEndpoint v) { this.whois = v; }
    }

    public static class ApiEndpoint {
        private String apiKey;
        private String url;
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public boolean isConfigured() { return apiKey != null && !apiKey.isBlank(); }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
    }
}
