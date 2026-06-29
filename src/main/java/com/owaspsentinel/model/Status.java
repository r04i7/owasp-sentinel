package com.owaspsentinel.model;

import java.awt.Color;

/**
 * Triage state for a finding. Drives colouring, the "hide noise" filter, and is
 * persisted so your verdicts survive a Burp restart.
 */
public enum Status {
    NEW("New", new Color(0x607D8B)),
    CONFIRMED("Confirmed", new Color(0xD32F2F)),       // a real, verified issue — stand out
    FALSE_POSITIVE("False positive", new Color(0x9E9E9E)),
    IGNORED("Ignored", new Color(0x9E9E9E));

    public final String label;
    public final Color color;

    Status(String label, Color color) {
        this.label = label;
        this.color = color;
    }

    /** FALSE_POSITIVE / IGNORED are "noise" the user may want hidden. */
    public boolean isNoise() {
        return this == FALSE_POSITIVE || this == IGNORED;
    }
}
