/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest;

import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.holderbinding.Proof;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.holderbinding.ProofType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.Map;
import java.util.Optional;

/**
 * Representation of an <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.2">OID4VCI Credential Request</a>
 * using the parameters for the pre-authenticated flow
 */
@Data
@Builder
@AllArgsConstructor
public class CredentialRequest {

    private String format;

    private Map<String, Object> proof;

    /**
     * If this request element is not present, the corresponding credential response returned is not encrypted
     */
    private CredentialResponseEncryption credentialResponseEncryption;

    public Optional<Proof> getProof(int acceptableProofTimeWindow) {
        var key = "proof_type";
        if (proof == null || proof.get(key) == null) {
            return Optional.empty();
        }
        if (proof.get(key).equals(ProofType.JWT.toString())) {
            Optional.ofNullable(proof.get("jwt"))
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .orElseThrow(() -> new IllegalArgumentException("jwt property needs to be present when proof_type is jwt"));
            return Optional.of(new ProofJwt(ProofType.JWT, proof.get(ProofType.JWT.toString()).toString(), acceptableProofTimeWindow));
        } else {
            throw new IllegalArgumentException("Any other proof type than jwt is not supported");
        }
    }
}