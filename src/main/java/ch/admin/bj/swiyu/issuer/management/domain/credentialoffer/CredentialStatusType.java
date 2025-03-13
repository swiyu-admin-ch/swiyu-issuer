/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import java.util.List;

public enum CredentialStatusType {
    OFFERED,
    CANCELLED,
    IN_PROGRESS,
    ISSUED,
    SUSPENDED,
    REVOKED,
    EXPIRED;

    /**
     * @return List of CredentialStatusType which can lead to "expire"
     */
    public static List<CredentialStatusType> getExpirableStates() {
        return List.of(CredentialStatusType.OFFERED, CredentialStatusType.IN_PROGRESS);
    }

    public boolean isIssuedToHolder() {
        return this != OFFERED && this != IN_PROGRESS && this != CANCELLED;
    }

    public boolean isDuringHolderInteraction() {
        return this == IN_PROGRESS;
    }
}
