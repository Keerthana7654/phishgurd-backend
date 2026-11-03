package com.phishguard.detection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RedirectResolverServiceTest {

    private final RedirectResolverService resolver = new RedirectResolverService();

    @Test
    void recognizesKnownShortenerDomains() {
        assertTrue(resolver.isShortener("bit.ly"));
        assertTrue(resolver.isShortener("tinyurl.com"));
        assertTrue(resolver.isShortener("BIT.LY"), "shortener check should be case-insensitive");
    }

    @Test
    void doesNotFlagOrdinaryDomainsAsShorteners() {
        assertFalse(resolver.isShortener("sbi.co.in"));
        assertFalse(resolver.isShortener("google.com"));
    }

    @Test
    void leavesNonShortenerUrlsUnchanged() {
        // No network call should happen for a non-shortener host — this
        // must return instantly and unchanged.
        String url = "https://www.sbi.co.in/personal-banking";
        assertEquals(url, resolver.resolveFinalUrl(url));
    }

    @Test
    void leavesMalformedUrlsUnchanged() {
        String malformed = "not a valid url";
        assertEquals(malformed, resolver.resolveFinalUrl(malformed));
    }
}
