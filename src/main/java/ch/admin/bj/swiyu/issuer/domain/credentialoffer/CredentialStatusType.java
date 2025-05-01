/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.List;

public enum CredentialStatusType {
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

    CredentialStatusType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return this.getDisplayName();
    }
    /**
     * @return List of CredentialStatusType which can lead to "expire"
     */
    public static List<CredentialStatusType> getExpirableStates() {
        return List.of(CredentialStatusType.OFFERED, CredentialStatusType.IN_PROGRESS);
    }

    public boolean isIssuedToHolder() {
        return this != OFFERED && this != IN_PROGRESS && this != CANCELLED && this != DEFERRED && this != READY;
    }

    public boolean isTerminalState() {
        return this == REVOKED || this == EXPIRED || this == CANCELLED;
    }

    public boolean isDuringHolderInteraction() {
        return this == IN_PROGRESS;
    }
}