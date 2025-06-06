/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.2.1">OID4VCI Proof Types</a>
 */
@Getter
@AllArgsConstructor
public enum ProofType {
    JWT("jwt", "openid4vci-proof+jwt");

    private final String displayName;
    /**
     * REQUIRED "typ": claim
     */
    private final String claimTyp;

    @Override
    public String toString() {
        return this.getDisplayName();
    }
}
