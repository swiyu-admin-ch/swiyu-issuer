/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.util.CollectionUtils;

import java.util.Arrays;
import java.util.Map;

public class CredentialRequestProofTypeValidator implements ConstraintValidator<CredentialRequestProofConstraint, Map<String, Object>> {
    @Override
    public void initialize(CredentialRequestProofConstraint constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
    }

    /**
     * Validates the Credential Request Proof according to <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.2.1">OID4VCI Spec</a>
     *
     * @param proof   credential request proof json to validate
     * @param context context in which the constraint is evaluated
     * @return true if the proof is a valid combination
     */
    @Override
    public boolean isValid(Map<String, Object> proof, ConstraintValidatorContext context) {
        if (CollectionUtils.isEmpty(proof)) {
            // proof entry itself is optional
            return true;
        }
        if (!proof.containsKey("proof_type")) {
            // if there is a proof entry, the proof_type is required
            return false;
        }
        var proofType = proof.get("proof_type").toString();
        // When proof_type is jwt, a proof object MUST include a jwt claim containing a JWT defined in Section 7.2.1.1.
        // When proof_type is cwt, a proof object MUST include a cwt claim containing a CWT defined in Section 7.2.1.3.
        // When proof_type is set to ldp_vp, the proof object MUST include a ldp_vp claim containing a W3C Verifiable Presentation defined in Section 7.2.1.2.
        // proof_type display name is equal to the claim
        // Not recognized proof type or missing claim
        return Arrays.stream(ProofTypeDto.values()).anyMatch(p -> p.getDisplayName().equals(proofType)) && proof.containsKey(proofType);

    }
}