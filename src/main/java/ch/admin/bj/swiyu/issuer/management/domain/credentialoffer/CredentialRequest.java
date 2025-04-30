/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import java.util.Map;

public record CredentialRequest(
        /**
         * Format of the requested credential. Only vc+sd-jwt format is supported
         */
        String format,
        /**
         * Proof for holder binding
         */
        Map<String, Object> proof,
        /**
         * If this request element is not present, the corresponding credential response returned is not encrypted
         */
        CredentialResponseEncryption credentialResponseEncryption
) {
}