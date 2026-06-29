package com.owaspsentinel.model;

import java.awt.Color;

/**
 * Finding severity, ordered most-to-least serious. Each carries a colour used
 * by the findings table renderer.
 */
public enum Severity {
    CRITICAL(4, new Color(0x9C27B0)),
    HIGH(3, new Color(0xD32F2F)),
    MEDIUM(2, new Color(0xF57C00)),
    LOW(1, new Color(0x1976D2)),
    INFO(0, new Color(0x607D8B));

    public final int rank;
    public final Color color;

    Severity(int rank, Color color) {
        this.rank = rank;
        this.color = color;
    }
}
