/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

public enum CredentialStatus {
    OFFERED("Offered"),
    CANCELLED("Cancelled"),
    IN_PROGRESS("Claiming in Progress"),

    // Status necessary for deferred flow
    DEFERRED("Deferred"),
    READY("Ready"),

    ISSUED("Issued"),
    SUSPENDED("Suspended"),
    REVOKED("Revoked"),
    EXPIRED("Expired");

    private final String displayName;

    CredentialStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return this.getDisplayName();
    }
}