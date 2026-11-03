package com.phishguard.detection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.Set;

/**
 * Follows redirect chains for known URL shorteners (bit.ly, tinyurl.com,
 * etc.) so the backend analyzes the REAL destination instead of just the
 * shortened wrapper. This matters most for the Android app and WhatsApp/SMS
 * phishing generally — shortened links are extremely common there (message
 * character limits), and without this, a phishing link hidden behind a
 * shortener was only ever caught by the weak "this is a shortener" signal
 * alone (10 points — stays in the "safe" bucket on its own).
 *
 * Deliberately NOT done client-side in the Chrome extension or the Android
 * app itself — fetching an attacker-controlled URL from the user's own
 * device/browser risks tipping off the attacker or loading something
 * unwanted. Doing it server-side, from the backend, is standard practice
 * for link-checking services (this is exactly what URL-safety scanners do).
 *
 * Only triggered for known shortener domains, not every link, to keep
 * normal-browsing latency low. Includes SSRF protection: refuses to follow
 * a redirect whose host resolves to a loopback, link-local, site-local
 * (private network), or multicast address — e.g. cloud metadata endpoints
 * like 169.254.169.254 — since this runs server-side against
 * attacker-influenced input and a malicious redirect chain could otherwise
 * be used to probe the backend's own internal network.
 */
@Service
public class RedirectResolverService {

    private static final Logger log = LoggerFactory.getLogger(RedirectResolverService.class);
    private static final int MAX_HOPS = 5;
    private static final int TIMEOUT_MS = 3000;

    public static final Set<String> SHORTENER_DOMAINS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
            "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id"
    );

    public boolean isShortener(String hostname) {
        return hostname != null && SHORTENER_DOMAINS.contains(hostname.toLowerCase());
    }

    /**
     * Returns the final destination URL after following redirects, or the
     * original URL unchanged if it's not a known shortener, resolution
     * fails or times out, or a hop looks like an SSRF attempt. Always
     * fails open to the original URL — a resolution failure should never
     * block the rest of the analysis pipeline.
     */
    public String resolveFinalUrl(String originalUrl) {
        String hostname;
        try {
            hostname = new URL(originalUrl).getHost();
        } catch (Exception e) {
            return originalUrl;
        }
        if (!isShortener(hostname)) {
            return originalUrl;
        }

        String currentUrl = originalUrl;
        for (int hop = 0; hop < MAX_HOPS; hop++) {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(currentUrl);

                if (!isSafeToFetch(url.getHost())) {
                    log.warn("Redirect resolution stopped — unsafe host: {}", url.getHost());
                    return currentUrl; // stop at the last known-safe hop
                }

                conn = (HttpURLConnection) url.openConnection();
                conn.setInstanceFollowRedirects(false);
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                conn.setRequestMethod("HEAD");
                conn.connect();

                int code = conn.getResponseCode();
                if (code >= 300 && code < 400) {
                    String location = conn.getHeaderField("Location");
                    if (location == null) break;
                    currentUrl = new URL(url, location).toString(); // resolves relative Location headers too
                } else {
                    break; // reached the real destination
                }
            } catch (Exception e) {
                log.warn("Redirect resolution for {} stopped early: {}", originalUrl, e.getMessage());
                break;
            } finally {
                if (conn != null) conn.disconnect();
            }
        }
        return currentUrl;
    }

    private boolean isSafeToFetch(String host) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            return !(addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                    || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()
                    || addr.isMulticastAddress());
        } catch (Exception e) {
            return false; // can't resolve — don't fetch it
        }
    }
}
