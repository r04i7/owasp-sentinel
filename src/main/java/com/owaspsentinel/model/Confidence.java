package com.owaspsentinel.model;

/**
 * How sure the passive heuristic is. Passive analysis can never be CERTAIN of an
 * exploit, so these reflect "how strong is the signal", matching Burp's vocabulary.
 */
public enum Confidence {
    FIRM,
    TENTATIVE,
    SPECULATIVE
}
