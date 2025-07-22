/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Representation of an <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.2">OID4VCI Credential Request</a>
 * using the parameters for the pre-authenticated flow
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CredentialRequestClass {

    private String format;

    private String credentialConfigurationId;

    @Nullable
    private Map<String, Object> proof;
    /**
     * If this request element is not present, the corresponding credential response returned is not encrypted
     */
    private CredentialResponseEncryptionClass credentialResponseEncryption;

    /**
     * Default constructor for the old credential flow.
     * Will be removed in a future version, as soon as the new credential flow is fully migrated
     *
     * @deprecated Use {@link #credentialResponseEncryption} instead.
     */
    @Deprecated(forRemoval = true)
    public CredentialRequestClass(String format, Map<String, Object> proof, CredentialResponseEncryptionClass credentialResponseEncryption) {
        this.format = format;
        this.proof = proof;
        this.credentialResponseEncryption = credentialResponseEncryption;
    }


    public CredentialRequestClass(String format, Map<String, Object> proofs, CredentialResponseEncryptionClass credentialResponseEncryption, String credentialConfigurationId) {
        this.format = format;
        this.credentialConfigurationId = credentialConfigurationId;
        this.proof = proofs;
        this.credentialResponseEncryption = credentialResponseEncryption;
    }

    public List<ProofJwt> getProofs(int acceptableProofTimeWindow, int nonceLifetimeSeconds) {

        if (proof == null) {
            return List.of();
        }

        var jwts = proof.get(ProofType.JWT.toString());

        // new v2 case
        if (jwts instanceof List<?>) {
            return ((List<?>) jwts).stream().map(proofJwt -> new ProofJwt(ProofType.JWT,
                            (String) proofJwt, acceptableProofTimeWindow, nonceLifetimeSeconds))
                    .toList();
        }

        return getProof(acceptableProofTimeWindow, nonceLifetimeSeconds)
                .map(List::of)
                .orElseGet(List::of);
    }

    public Optional<ProofJwt> getProof(int acceptableProofTimeWindow, int nonceLifetimeSeconds) {
        final var PROOF_TYPE_KEY = "proof_type";
        // No Proof provided by Holder
        if (proof == null) {
            return Optional.empty();
        }

        if (proof.get(PROOF_TYPE_KEY).equals(ProofType.JWT.toString())) {
            var proofJwt = Optional.ofNullable(proof.get(ProofType.JWT.toString()))
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .orElseThrow(() -> new IllegalArgumentException("jwt property needs to be present when proof_type is jwt"));
            return Optional.of(new ProofJwt(ProofType.JWT, proofJwt, acceptableProofTimeWindow, nonceLifetimeSeconds));
        } else {
            throw new IllegalArgumentException("Any other proof type than jwt is not supported");
        }
    }
}