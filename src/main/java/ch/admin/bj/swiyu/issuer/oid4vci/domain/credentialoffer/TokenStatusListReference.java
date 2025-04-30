/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import java.util.Map;

/**
 * Referenced Token
 * See <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-status-list-token-in-jwt-fo">spec</a>
 * Status List reference written into VC
 * Should be added as "status_list" to a status json object in the vc
 */
public record TokenStatusListReference(int idx, String uri,
                                       String type) implements VerifiableCredentialStatusReference {
    @Override
    public Map<String, Object> createVCRepresentation() {
        return Map.of("status", Map.of("status_list", Map.of("idx", idx, "uri", uri, "type", type)));
    }
}
