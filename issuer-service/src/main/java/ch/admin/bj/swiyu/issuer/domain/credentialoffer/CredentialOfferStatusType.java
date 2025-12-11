/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import lombok.Getter;

import java.util.List;

@Getter
public enum CredentialOfferStatusType {
    OFFERED("Offered"),
    CANCELLED("Cancelled"),
    IN_PROGRESS("Claiming in Progress"),
    // Status necessary for deferred flow
    DEFERRED("Deferred"),
    READY("Ready"),
    ISSUED("Issued"),
    EXPIRED("Expired");

    private final String displayName;

    CredentialOfferStatusType(String displayName) {
        this.displayName = displayName;
    }

    /**
     * @return List of CredentialStatusType which can lead to "expire"
     */
    public static List<CredentialOfferStatusType> getExpirableStates() {
        return List.of(CredentialOfferStatusType.OFFERED, CredentialOfferStatusType.IN_PROGRESS, CredentialOfferStatusType.DEFERRED, CredentialOfferStatusType.READY);
    }

    @Override
    public String toString() {
        return this.getDisplayName();
    }

    public boolean isProcessable() {
        return this == OFFERED || this == IN_PROGRESS || this == DEFERRED || this == READY;
    }

    public boolean isTerminalState() {
        return this == EXPIRED || this == CANCELLED;
    }
}