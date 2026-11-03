package com.phishguard.detection;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class HeuristicDetectorsTest {

    private final HeuristicDetectors detectors = new HeuristicDetectors();

    @Test
    void detectsTyposquatDomain() {
        DetectionResult result = detectors.checkTyposquat("goggle.com");
        assertTrue(result.fired(), "goggle.com should be flagged as a typosquat of google.com");
    }

    @Test
    void doesNotFlagLegitimateDomain() {
        DetectionResult result = detectors.checkTyposquat("google.com");
        assertFalse(result.fired(), "google.com itself must never be flagged as its own typosquat");
    }

    @Test
    void detectsIpLiteralUrl() {
        assertTrue(detectors.checkIpLiteral("192.168.1.10").fired());
        assertFalse(detectors.checkIpLiteral("github.com").fired());
    }

    @Test
    void detectsPunycodeDomain() {
        assertTrue(detectors.checkPunycode("xn--pple-43d.com").fired());
        assertFalse(detectors.checkPunycode("apple.com").fired());
    }

    @Test
    void detectsBrandInSubdomain() {
        DetectionResult result = detectors.checkSubdomainImpersonation("google.com.fake-domain.xyz");
        assertTrue(result.fired());
    }

    @Test
    void detectsSuspiciousKeywords() {
        DetectionResult result = detectors.checkKeywords("secure-login-update.example.com", "/verify");
        assertTrue(result.fired());
    }

    @Test
    void registrableDomainStripsSubdomains() {
        assertEquals("example.com", detectors.registrableDomain("a.b.example.com"));
    }

    // --- Regression tests for the fake-banking-site detection bug ---
    // Originally, "paypaI-secure-login.tk" scored too low to trigger a
    // warning because typosquat matching compared the WHOLE hyphenated
    // label ("paypai-secure-login") against "paypal" instead of the
    // individual word "paypai" within it. Fixed by tokenizing the label.

    @Test
    void detectsTyposquatHiddenInHyphenatedLabel() {
        DetectionResult result = detectors.checkTyposquat("paypai-secure-login.tk");
        assertTrue(result.fired(),
                "the 'paypai' token should be caught as a paypal typosquat even inside a longer hyphenated label");
        DetectionResult res = detectors.checkTyposquat("paypai.com");
        assertTrue(res.fired(),
                "the 'paypai' token should be caught as a paypal typosquat even inside a longer hyphenated label");
        DetectionResult re = detectors.checkTyposquat("paypai.in");
        assertTrue(re.fired(),
                "the 'paypai' token should be caught as a paypal typosquat even inside a longer hyphenated label");
    }

    @Test
    void detectsBrandNamePrefixEmbeddedInFakeBankingDomain() {
        DetectionResult result = detectors.checkTyposquat("icici-bank-kyc-update.tk");
        assertTrue(result.fired(), "icicibank.com's brand prefix 'icici' embedded in a longer fake label should fire");
    }

    @Test
    void detectsExactBrandNameEmbeddedInUnrelatedDomain() {
        DetectionResult result = detectors.checkTyposquat("hdfcbank-netbanking-verify.xyz");
        assertTrue(result.fired(),
                "an exact brand-name token ('hdfcbank') embedded in an unrelated domain should fire, not be excluded for 'too perfect' a match");
    }

    @Test
    void doesNotFlagUnrelatedLegitimateFinanceSite() {
        DetectionResult result = detectors.checkTyposquat("icicidirect.com");
        assertFalse(result.fired(),
                "a real, unrelated finance domain that merely starts similarly should not false-positive");
    }

    // --- Regression tests for the compound-TLD false positive ---
    // Originally, "www.canarabank.bank.in" and "www.sbi.co.in" were flagged
    // as suspicious/moderate because the naive domain parser treated the
    // last TWO labels as the whole registrable domain, so "bank.in" and
    // "co.in" were mistaken for the actual domain and "canarabank"/"sbi"
    // were mistaken for suspicious subdomains or generic-word "typosquats"
    // (e.g. "bank" matching as a truncation of "bankofamerica"). Fixed with
    // a curated compound-TLD list and a length-ratio guard on the brand
    // fragment prefix rule.

    @Test
    void doesNotFlagGenuineIndianBankOnCompoundTld() {
        DetectionResult typosquat = detectors.checkTyposquat("www.canarabank.bank.in");
        DetectionResult subdomain = detectors.checkSubdomainImpersonation("www.canarabank.bank.in");
        assertFalse(typosquat.fired(), "'bank' should not falsely match as a truncated 'bankofamerica'");
        assertFalse(subdomain.fired(), "canarabank.bank.in is canarabank's own domain, not a fake subdomain");
    }

    @Test
    void doesNotFlagSbiOnCoInDomain() {
        DetectionResult subdomain = detectors.checkSubdomainImpersonation("www.sbi.co.in");
        assertFalse(subdomain.fired(),
                "sbi.co.in is SBI's own registrable domain, not 'sbi' as a fake subdomain of co.in");
    }

    @Test
    void registrableDomainHandlesCompoundTld() {
        assertEquals("sbi.co.in", detectors.registrableDomain("www.sbi.co.in"));
        assertEquals("canarabank.bank.in", detectors.registrableDomain("www.canarabank.bank.in"));
    }

    @Test
    void stillDetectsRealDomainEmbeddedAsFakeSubdomain() {
        // sbi.co.in appearing as a fake SUBdomain of an unrelated domain is
        // still exactly the attack pattern this check exists to catch.
        DetectionResult result = detectors.checkSubdomainImpersonation("sbi.co.in.fake-verify.tk");
        assertTrue(result.fired(),
                "a real bank domain embedded as a fake subdomain of an unrelated domain should still fire");
    }

    // --- Regression tests: a brand with TWO legitimate domains ---
    // SBI genuinely operates both sbi.co.in and sbi.bank.in. Originally,
    // sbi.bank.in was flagged as "the exact brand name sbi.co.in in an
    // unrelated domain" (100% match on the wrong whitelist entry) because
    // only sbi.co.in was recognized. Fixed by adding sbi.bank.in as a
    // second recognized domain, and by making the subdomain-impersonation
    // check recognize ANY known brand domain up front rather than
    // comparing against one specific brand entry at a time (which broke
    // once a brand had two legitimate domains in the list).

    @Test
    void doesNotFlagSecondLegitimateDomainOfSameBrand() {
        DetectionResult typosquat = detectors.checkTyposquat("sbi.bank.in");
        assertFalse(typosquat.fired(), "sbi.bank.in is SBI's own second domain, not an impersonation of sbi.co.in");
    }

    @Test
    void doesNotFlagSubdomainOfSecondLegitimateDomain() {
        DetectionResult typosquat = detectors.checkTyposquat("onlinesbi.sbi.bank.in");
        DetectionResult subdomain = detectors.checkSubdomainImpersonation("onlinesbi.sbi.bank.in");
        assertFalse(typosquat.fired());
        assertFalse(subdomain.fired(),
                "onlinesbi.sbi.bank.in is a subdomain of SBI's own legitimate domain, not impersonation");
    }

    // --- Regression test: truncated-compound-TLD typosquat ---
    // "sbi.co" (missing the ".in") is a real, deliberate phishing pattern —
    // dropping just the country-code portion of a compound TLD while
    // keeping the rest. This must score high-confidence on its own,
    // without weakening the (correct, legitimate) sbi.co.in / sbi.bank.in
    // entries this file's other tests confirm stay safe.

    @Test
    void flagsTruncatedCompoundTldAsHighConfidence() {
        DetectionResult result = detectors.checkTyposquat("sbi.co");
        assertTrue(result.fired(), "sbi.co should be flagged as a truncated-TLD typosquat of sbi.co.in");
        assertTrue(result.scoreContribution() >= 76,
                "a truncated-TLD typosquat should score at dangerous-level confidence on its own");
    }

    @Test
    void doesNotFlagRealCompoundTldDomainsAsTruncated() {
        assertFalse(detectors.checkTyposquat("sbi.co.in").fired());
        assertFalse(detectors.checkTyposquat("sbi.bank.in").fired());
    }

    // --- Regression test: truncation in the OTHER direction ---
    // The original fix only caught dropping the LAST part of a compound
    // TLD (sbi.co.in -> sbi.co). "canarabank.in" drops the FIRST part
    // instead (canarabank.bank.in -> canarabank.in) and must be caught
    // just as confidently, without flagging canarabank.com or
    // canarabank.bank.in themselves — both are the bank's own real,
    // currently-active domains (canarabank.com still used for official
    // email; canarabank.bank.in is their RBI-mandated migrated site).

    @Test
    void flagsTruncationInEitherDirection() {
        DetectionResult sbiIn = detectors.checkTyposquat("sbi.in");
        DetectionResult canarabankIn = detectors.checkTyposquat("canarabank.in");
        assertTrue(sbiIn.fired(), "sbi.in should be flagged as a truncated-TLD typosquat");
        assertTrue(canarabankIn.fired(),
                "canarabank.in should be flagged as a truncated-TLD typosquat (drops 'bank' from canarabank.bank.in)");
        assertTrue(sbiIn.scoreContribution() >= 76);
        assertTrue(canarabankIn.scoreContribution() >= 76);
    }

    @Test
    void doesNotFlagCanaraBanksTwoRealDomains() {
        assertFalse(detectors.checkTyposquat("canarabank.com").fired(),
                "canarabank.com is the bank's own legacy/email domain");
        assertFalse(detectors.checkTyposquat("canarabank.bank.in").fired(),
                "canarabank.bank.in is the bank's current official domain");
    }

    // --- Regression tests: the architectural .bank.in rule ---
    // Since Oct 2025, India's RBI restricts .bank.in registration
    // exclusively to regulated banks (via IDRBT/NIXI) — a phishing site
    // cannot obtain one. isBankInDomain() trusts ANY such domain rather
    // than requiring every bank's own registrations to be individually
    // curated, which cannot keep up with reality (banks register several,
    // e.g. Bank of Maharashtra's netbanking-specific "mahaconnect.bank.in").

    @Test
    void trustsAnyBankInDomainEvenIfNotIndividuallyCurated() {
        // Neither of these appears anywhere in KNOWN_BRAND_DOMAINS — the
        // architectural rule alone must recognize them as legitimate.
        assertFalse(detectors.checkTyposquat("indianbank.bank.in").fired());
        assertFalse(detectors.checkTyposquat("somesmallregionalbank.bank.in").fired());
    }

    @Test
    void isBankInDomainRecognizesOnlyRealBankInSuffix() {
        assertTrue(detectors.isBankInDomain("sbi.bank.in"));
        assertTrue(detectors.isBankInDomain("mahaconnect.bank.in"));
        assertFalse(detectors.isBankInDomain("sbi.co.in"), "co.in is a different suffix, not bank.in");
        assertFalse(detectors.isBankInDomain("fake-sbi-bank-in-verify.tk"),
                "must match the actual TLD, not just contain the string 'bank.in'");
    }

    // --- Regression test: a whitelisted legacy domain colliding with its
    // own bank's separate .bank.in entry ---
    // Adding "bankofbaroda.in" (legacy) and "bankofbaroda.bank.in" (new)
    // together initially caused "bankofbaroda.in" to trip the truncated-TLD
    // check against its OWN other entry, since dropping "bank" from
    // "bankofbaroda.bank.in" looks identical to "bankofbaroda.in". Fixed by
    // short-circuiting the whole typosquat check for anything already in
    // KNOWN_BRAND_DOMAINS, before the truncated-TLD check ever runs.

    @Test
    void doesNotFlagLegacyDomainAgainstItsOwnBanksSeparateBankInEntry() {
        assertFalse(detectors.checkTyposquat("bankofbaroda.in").fired(),
                "bankofbaroda.in is itself a whitelisted legitimate domain and must not collide with bankofbaroda.bank.in");
    }

    // --- Legacy bank domains: moderate, not dangerous, not clean ---
    // These are still owned by the banks (WHOIS-verified for icicibank.com;
    // canarabank.com still listed in Canara Bank's 2026 SEBI filing), so a
    // "dangerous" verdict would be false — but a clean 0 would hide that the
    // bank has moved to its .bank.in address.

    @Test
    void legacyBankDomainsScoreModerateNotDangerous() {
        assertEquals(30, detectors.checkLegacyDomain("icicibank.com").scoreContribution());
        assertEquals(30, detectors.checkLegacyDomain("www.sbi.co.in").scoreContribution());
        assertEquals(0, detectors.checkLegacyDomain("icici.bank.in").scoreContribution());
    }

    @Test
    void keywordCheckIsSkippedOnVerifiedBankDomains() {
        // "bank" is literally part of "icicibank" — not a warning sign there.
        assertFalse(detectors.checkKeywords("icicibank.com", "/netbanking/login").fired());
        assertFalse(detectors.checkKeywords("icici.bank.in", "/login").fired());
        // ...but still fires on a domain we have NOT verified.
        assertTrue(detectors.checkKeywords("secure-login-update.example.com", "/verify").fired());
    }

    @Test
    void indianBankNameOnNonBankInAddressIsFlagged() {
        assertTrue(detectors.checkIndianBankName("indianbank.in").fired());
        assertFalse(detectors.checkIndianBankName("indianbank.bank.in").fired(), ".bank.in is the correct address");
        assertFalse(detectors.checkIndianBankName("icicibank.com").fired(),
                "already handled as a verified legacy domain");
        assertFalse(detectors.checkIndianBankName("example.com").fired());
    }
}
