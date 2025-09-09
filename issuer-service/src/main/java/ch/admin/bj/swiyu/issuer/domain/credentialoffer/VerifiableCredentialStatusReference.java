/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.Map;

@FunctionalInterface
public interface VerifiableCredentialStatusReference {
    /**
     * Create a hashmap as to be used in the claims of a verifiable credential
     */
    Map<String, Object> createVCRepresentation();
}
