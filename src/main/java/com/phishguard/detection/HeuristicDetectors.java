package com.phishguard.detection;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Server-side mirror of the extension's client-side detector (lib/detector.js),
 * so users get identical scoring whether the extension is running standalone
 * or against this backend. This class implements the checks that need no
 * external API key; ThreatIntelService layers the API-key-dependent checks
 * (Safe Browsing, VirusTotal, AbuseIPDB, WHOIS) on top.
 */
@Component
public class HeuristicDetectors {

    private static final List<String> KNOWN_BRAND_DOMAINS = List.of(
            // Tech / social
            "google.com", "github.com", "amazon.com", "microsoft.com",
            "linkedin.com", "facebook.com", "instagram.com", "apple.com",
            "openai.com", "netflix.com", "twitter.com", "x.com", "whatsapp.com",
            "dropbox.com", "adobe.com", "yahoo.com",
            // Global banking / payments
            "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
            "citibank.com", "hsbc.com", "americanexpress.com", "venmo.com", "stripe.com",
            // Indian banking / payments — public sector banks (all 12, per
            // RBI's 2025 mandate that regulated banks migrate to .bank.in;
            // both legacy and new domains listed where confirmed). See
            // isBankInDomain() further down for why this list doesn't need
            // to be exhaustive going forward.
            "sbi.co.in", "sbi.bank.in",                              // State Bank of India
            "pnbindia.in", "pnb.bank.in",                            // Punjab National Bank
            "bankofbaroda.in", "bankofbaroda.bank.in",               // Bank of Baroda
            "canarabank.com", "canarabank.bank.in",                  // Canara Bank
            "unionbankofindia.co.in", "unionbankofindia.bank.in", "unionbankonline.bank.in", // Union Bank of India
            "bankofindia.co.in",                                     // Bank of India
            "centralbank.bank.in",                                   // Central Bank of India
            "iob.bank.in",                                           // Indian Overseas Bank
            "bankofmaharashtra.bank.in", "mahaconnect.bank.in",      // Bank of Maharashtra
            "punjabandsind.bank.in",                                 // Punjab & Sind Bank
            // Indian banking — major private banks
            "icici.bank.in",                        // ICICI Bank
             "hdfc.bank.in",                          // HDFC Bank
             "axis.bank.in",                          // Axis Bank
             "kotak.bank.in",                            // Kotak Mahindra Bank
            "indusind.bank.in",                                          // IndusInd Bank
            "federal.bank.in",                                       // Federal Bank
            "idfcfirst.bank.in",                                     // IDFC FIRST Bank
            // Indian payments
            "paytm.com", "phonepe.com", "idbibank.in"
    );

    /**
     * Legacy domain -> current official .bank.in domain, for banks that
     * have completed the RBI-mandated migration. Still owned and operated
     * by the banks themselves (verified via WHOIS for icicibank.com;
     * Canara Bank's 2026 SEBI filing still lists canarabank.com), so NOT
     * flagged dangerous — but no longer the bank's current official
     * address, so they score into "moderate" rather than being left fully
     * clean. Only pairs where both domains are independently confirmed.
     */
    // Names of Indian banks (core label only). Since the RBI's .bank.in
    // mandate a bank's official site should live on <name>.bank.in, so one of
    // these names on any other address deserves a closer look.
    private static final Set<String> INDIAN_BANK_NAMES = Set.of("indianbank", "ucobank", "yesbank", "idfcfirstbank", "rblbank", "bandhanbank", "federalbank", "southindianbank", "karnatakabank", "jkbank", "dcbbank", "aubank", "equitasbank", "statebankofindia", "centralbankofindia", "indianoverseasbank", "bankofmaharashtra", "punjabandsindbank", "unionbank", "canarabank", "bankofindia", "bankofbaroda", "punjabnationalbank", "hdfcbank", "icicibank", "axisbank", "kotakbank", "kotakmahindrabank", "indusindbank", "idbibank", "sbi", "pnb", "iob", "uco", "hdfc", "icici", "kotak");

    private static final Map<String, String> LEGACY_TO_BANKIN = Map.of(
            "sbi.co.in", "sbi.bank.in",
            "bankofbaroda.in", "bankofbaroda.bank.in",
            "canarabank.com", "canarabank.bank.in",
            "unionbankofindia.co.in", "unionbankofindia.bank.in",
            "icicibank.com", "icici.bank.in",
            "hdfcbank.com", "hdfc.bank.in",
            "axisbank.com", "axis.bank.in",
            "kotak.com", "kotak.bank.in",
            "pnbindia.in", "pnb.bank.in"
    );

    private static final List<String> SUSPICIOUS_KEYWORDS = List.of(
            "login", "secure", "verify", "update", "bank", "gift", "bonus",
            "reward", "claim", "account", "payment", "invoice", "signin",
            "wallet", "confirm", "suspend", "unlock", "billing", "recover",
            "password", "authenticate", "security-alert",
            // Banking/payment-specific
            "netbanking", "upi", "otp", "kyc", "creditcard", "debitcard", "ifsc", "atm"
    );

    // Shortener list lives in RedirectResolverService.SHORTENER_DOMAINS now —
    // single source of truth, since that service also needs it to decide
    // which domains to actually follow redirects for.

    // A small curated set of common compound/multi-part public suffixes.
    // NOT a full public-suffix-list implementation (that's a several
    // thousand-entry list) — deliberately scoped to country-code TLD
    // patterns likely to matter here, especially India (many Indian banks
    // use .co.in/.bank.in rather than .com), so domains like "sbi.co.in"
    // are correctly recognized as the registrant's real domain instead of
    // "sbi" being misread as a suspicious subdomain of "co.in".
    private static final Set<String> MULTI_PART_SUFFIXES = Set.of(
            "co.in", "net.in", "org.in", "gov.in", "ac.in", "res.in", "bank.in", "nic.in", "gen.in",
            "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk",
            "com.au", "net.au", "org.au", "gov.au", "edu.au",
            "co.nz", "org.nz", "govt.nz",
            "co.jp", "or.jp", "ne.jp",
            "co.za", "org.za", "gov.za",
            "com.br", "net.br", "org.br", "gov.br",
            "com.sg", "co.id", "com.my"
    );

    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");

    public boolean isIpLiteral(String hostname) {
        if (IPV4.matcher(hostname).matches()) return true;
        return hostname.contains(":") && hostname.replaceAll("[\\[\\]]", "").matches("^[0-9a-fA-F:]+$");
    }

    public boolean isPunycode(String hostname) {
        for (String label : hostname.split("\\.")) {
            if (label.startsWith("xn--")) return true;
        }
        return false;
    }

    /** Number of trailing labels that make up the public suffix (1 normally, 2 for compound TLDs like co.in). */
    public int suffixLabelCount(String hostname) {
        String[] parts = hostname.split("\\.");
        if (parts.length >= 2) {
            String lastTwo = parts[parts.length - 2] + "." + parts[parts.length - 1];
            if (MULTI_PART_SUFFIXES.contains(lastTwo)) return 2;
        }
        return 1;
    }

    public String registrableDomain(String hostname) {
        String[] parts = hostname.split("\\.");
        int suffixLen = suffixLabelCount(hostname);
        if (parts.length <= suffixLen + 1) return hostname;
        StringBuilder sb = new StringBuilder();
        for (int i = parts.length - (suffixLen + 1); i < parts.length; i++) {
            if (sb.length() > 0) sb.append(".");
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    /**
     * Recognizes ANY domain ending in ".bank.in" as an inherently
     * trustworthy banking domain — not via a curated list, but
     * architecturally. Since October 2025, India's RBI has mandated that
     * only IDRBT/NIXI-vetted, RBI-regulated banks may register under this
     * TLD at all; an unregulated party or phishing operation cannot obtain
     * one. This means KNOWN_BRAND_DOMAINS never needs to keep up with
     * every bank's own dedicated .bank.in registration (many banks
     * register several, e.g. Bank of Maharashtra's "mahaconnect.bank.in"
     * for net banking) — this single rule covers all of them, present and
     * future, without manual upkeep. It does NOT cover banks' legacy
     * .com/.co.in domains from before the migration — those still rely on
     * the curated list.
     */
    public boolean isBankInDomain(String hostname) {
        String[] parts = hostname.split("\\.");
        if (parts.length < 3) return false;
        String lastTwo = parts[parts.length - 2] + "." + parts[parts.length - 1];
        return "bank.in".equals(lastTwo);
    }

    /**
     * Splits a domain label like "paypai-secure-login" into ["paypai",
     * "secure", "login"] so typosquat matching compares against each
     * meaningful word instead of the whole hyphenated string (which almost
     * never resembles a short brand name once other words are appended).
     */
    public List<String> tokenize(String label) {
        List<String> tokens = new ArrayList<>();
        for (String t : label.split("[^a-zA-Z0-9]+")) {
            if (t.length() >= 3) tokens.add(t.toLowerCase());
        }
        if (!tokens.contains(label)) tokens.add(label);
        return tokens;
    }

    public double shannonEntropy(String str) {
        if (str.isEmpty()) return 0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : str.toCharArray()) freq.merge(c, 1, Integer::sum);
        double entropy = 0;
        for (int count : freq.values()) {
            double p = (double) count / str.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    public DetectionResult checkProtocol(URI uri) {
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            return new DetectionResult("protocol", 12, "Site does not use HTTPS.");
        }
        return new DetectionResult("protocol", 0, null);
    }

    public DetectionResult checkIpLiteral(String hostname) {
        if (isIpLiteral(hostname)) {
            return new DetectionResult("ipLiteral", 25, "URL uses a raw IP address instead of a domain name.");
        }
        return new DetectionResult("ipLiteral", 0, null);
    }

    public DetectionResult checkPunycode(String hostname) {
        if (isPunycode(hostname)) {
            return new DetectionResult("punycode", 20, "Domain uses Punycode encoding (possible homograph attack).");
        }
        return new DetectionResult("punycode", 0, null);
    }

    public DetectionResult checkTyposquat(String hostname) {
        String domain = registrableDomain(hostname);
        String candidateLabel = domain.split("\\.")[0];
        List<String> candidateTokens = tokenize(candidateLabel);

        if (isBankInDomain(hostname) || KNOWN_BRAND_DOMAINS.contains(domain)) {
            // Either an architecturally-verified *.bank.in domain, or
            // already an exact match in the curated list — independently
            // confirmed legitimate either way. Skip typosquat matching
            // entirely; without this, a bank's own legacy domain (e.g.
            // "bankofbaroda.in") can accidentally trip the truncated-TLD
            // check below against that SAME bank's separate .bank.in
            // entry ("bankofbaroda.bank.in"), since it happens to look
            // like a truncated version of it.
            return new DetectionResult("typosquat", 0, null);
        }

        String closestBrand = null;
        double closestSimilarity = 0;

        // Special case, checked first: a domain that matches a known
        // compound-TLD brand's core name exactly but keeps only ONE piece
        // of its real multi-part TLD — e.g. "sbi.co" (drops ".in" from
        // "sbi.co.in") or "canarabank.in" (drops "bank" from
        // "canarabank.bank.in"). Either direction is a deliberate,
        // well-known phishing technique — keeping just one recognizable
        // fragment of the real compound TLD reads as nearly identical at a
        // glance — so it's scored high-confidence on its own rather than
        // through the generic similarity formula.
        for (String brand : KNOWN_BRAND_DOMAINS) {
            String[] brandParts = brand.split("\\.");
            if (brandParts.length < 3) continue; // only applies to compound-TLD brands like sbi.co.in
            String brandCore = brandParts[0];
            List<String> brandSuffixParts = Arrays.asList(Arrays.copyOfRange(brandParts, 1, brandParts.length));
            String[] domainParts = domain.split("\\.");
            if (domainParts.length == 2 && domainParts[0].equals(brandCore) && !domain.equals(brand)) {
                String domainSuffix = domainParts[1];
                if (brandSuffixParts.contains(domainSuffix)) {
                    int score = 80;
                    String reason = String.format(
                            "Domain matches \"%s\"'s name but is missing part of its real top-level domain — a truncated-TLD typosquat.",
                            brand);
                    return new DetectionResult("typosquat", score, reason);
                }
            }
        }

        for (String brand : KNOWN_BRAND_DOMAINS) {
            if (domain.equals(brand)) {
                return new DetectionResult("typosquat", 0, null); // legitimate domain
            }
            String brandName = brand.split("\\.")[0];

            for (String token : candidateTokens) {
                double sim = 0;

                if (Math.abs(token.length() - brandName.length()) <= 3) {
                    sim = Math.max(sim, LevenshteinUtil.similarity(token, brandName));
                }

                // Two directions, two different false-positive risks:
                //  - token.startsWith(brandName): a short, curated real brand
                //    name (e.g. "sbi") is embedded at the start of a longer,
                //    likely-fake token (e.g. "sbi0nline"). Low risk since
                //    brandName is always a real, curated identifier.
                //  - brandName.startsWith(token): the domain's token is a
                //    fragment/truncation of a long brand name (e.g. "icici"
                //    of "icicibank"). HIGH risk on its own — any short,
                //    common word that happens to prefix some brand's full
                //    name would match (e.g. "bank" prefixes
                //    "bankofamerica", but "bank" is generic and appears in
                //    countless legitimate bank domains). Require the token
                //    to cover a real majority of the brand name, not just
                //    any coincidental prefix.
                boolean tokenEmbedsBrand = brandName.length() >= 3 && token.length() >= 4
                        && token.startsWith(brandName);
                boolean tokenIsBrandFragment = !tokenEmbedsBrand
                        && brandName.length() >= 3 && token.length() >= 4
                        && brandName.startsWith(token)
                        && (double) token.length() / brandName.length() >= 0.5;

                if (tokenEmbedsBrand || tokenIsBrandFragment) {
                    sim = Math.max(sim, 0.85);
                }

                if (sim > closestSimilarity) {
                    closestSimilarity = sim;
                    closestBrand = brand;
                }
            }
        }

        if (closestBrand != null && closestSimilarity >= 0.72) {
            int score = (int) Math.round(35 * closestSimilarity);
            String label = closestSimilarity >= 0.999 ? "contains the exact brand name" : "closely resembles";
            String reason = String.format(
                    "Domain %s \"%s\" (similarity %.0f%%) in an unrelated domain — possible impersonation.",
                    label, closestBrand, closestSimilarity * 100);
            return new DetectionResult("typosquat", score, reason);
        }
        return new DetectionResult("typosquat", 0, null);
    }

    public DetectionResult checkSubdomainImpersonation(String hostname) {
        String[] labels = hostname.split("\\.");
        String domain = registrableDomain(hostname);
        if (isBankInDomain(hostname) || KNOWN_BRAND_DOMAINS.contains(domain)) {
            return new DetectionResult("subdomainImpersonation", 0, null); // architecturally or explicitly recognized as legitimate
        }
        int suffixLen = suffixLabelCount(hostname);
        if (labels.length > suffixLen + 1) {
            String subLabels = String.join(".", Arrays.copyOf(labels, labels.length - (suffixLen + 1)));
            for (String brand : KNOWN_BRAND_DOMAINS) {
                String brandName = brand.split("\\.")[0];
                if (subLabels.contains(brandName)) {
                    return new DetectionResult("subdomainImpersonation", 30,
                            String.format("\"%s\" appears in a subdomain of a different domain (%s) — classic brand-impersonation pattern.",
                                    brandName, domain));
                }
            }
        }
        return new DetectionResult("subdomainImpersonation", 0, null);
    }

    public DetectionResult checkSubdomainDepth(String hostname) {
        if (hostname.split("\\.").length >= 5) {
            return new DetectionResult("subdomainDepth", 10, "Unusually deep subdomain chain.");
        }
        return new DetectionResult("subdomainDepth", 0, null);
    }

    /** True if this domain is already independently confirmed legitimate — via the .bank.in rule or the curated list. */
    public boolean isAlreadyKnownLegit(String hostname) {
        return isBankInDomain(hostname) || KNOWN_BRAND_DOMAINS.contains(registrableDomain(hostname));
    }

    /**
     * Legacy bank domain — not dangerous (still bank-owned), but no longer
     * the bank's current official address. Scored into "moderate" so it is
     * visibly distinguished from the current .bank.in domain.
     */
    public DetectionResult checkLegacyDomain(String hostname) {
        String current = LEGACY_TO_BANKIN.get(registrableDomain(hostname));
        if (current != null) {
            return new DetectionResult("legacyDomain", 30,
                    "This is a retired/legacy domain — the bank's current official address is " + current
                            + ". Still bank-owned, not flagged as dangerous, but prefer the current domain.");
        }
        return new DetectionResult("legacyDomain", 0, null);
    }

    /**
     * An Indian bank's name on an address that isn't .bank.in and isn't a
     * domain we've independently verified. Skipped when the typosquat check
     * already fires (no double-counting). Moderate, not dangerous: the name
     * alone can't tell a fake from an old bank-owned address.
     */
    public DetectionResult checkIndianBankName(String hostname) {
        if (isAlreadyKnownLegit(hostname) || checkTyposquat(hostname).fired()) {
            return new DetectionResult("indianBankName", 0, null);
        }
        String core = registrableDomain(hostname).split("\\.")[0];
        if (INDIAN_BANK_NAMES.contains(core)) {
            return new DetectionResult("indianBankName", 30,
                    "Uses an Indian bank's name but is not on a .bank.in address — RBI requires banks' official sites to be on .bank.in. Verify directly with the bank before entering any details.");
        }
        return new DetectionResult("indianBankName", 0, null);
    }

    public DetectionResult checkKeywords(String hostname, String path) {
        // Skipped for already-verified-legitimate domains: a bank's own
        // name/pages naturally contain "bank", "login", "netbanking" etc.
        if (isAlreadyKnownLegit(hostname)) {
            return new DetectionResult("keywords", 0, null);
        }
        List<String> matched = new ArrayList<>();
        String haystack = (hostname + " " + path).toLowerCase();
        for (String kw : SUSPICIOUS_KEYWORDS) {
            if (haystack.contains(kw)) matched.add(kw);
        }
        if (!matched.isEmpty()) {
            int score = Math.min(20, matched.size() * 6);
            String preview = String.join(", ", matched.subList(0, Math.min(4, matched.size())));
            return new DetectionResult("keywords", score, "Contains suspicious keyword(s): " + preview + ".");
        }
        return new DetectionResult("keywords", 0, null);
    }

    public DetectionResult checkEntropy(String hostname) {
        String mainLabel = registrableDomain(hostname).split("\\.")[0];
        double entropy = shannonEntropy(mainLabel);
        if (mainLabel.length() >= 8 && entropy >= 3.6) {
            return new DetectionResult("entropy", 12, "Domain name has high randomness (possible auto-generated phishing domain).");
        }
        return new DetectionResult("entropy", 0, null);
    }

    public DetectionResult checkShortener(String hostname) {
        String domain = registrableDomain(hostname);
        if (RedirectResolverService.SHORTENER_DOMAINS.contains(domain)) {
            return new DetectionResult("shortener", 10, "URL shortener detected — final destination is hidden.");
        }
        return new DetectionResult("shortener", 0, null);
    }
}
