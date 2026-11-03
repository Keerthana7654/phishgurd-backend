package com.phishguard.detection;

/** A single detector's contribution to the overall score, plus a human-readable reason if it fired. */
public record DetectionResult(String checkName, int scoreContribution, String reason) {
    public boolean fired() {
        return scoreContribution > 0 && reason != null;
    }
}
