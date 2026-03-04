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

    private String credentialConfigurationId;

    @Nullable
    private Map<String, Object> proof;

    /**
     * If this request element is not present, the corresponding credential response returned is not encrypted
     */
    private CredentialResponseEncryptionClass credentialResponseEncryption;


    public CredentialRequestClass(Map<String, Object> proofs, CredentialResponseEncryptionClass credentialResponseEncryption, String credentialConfigurationId) {
        this.credentialConfigurationId = credentialConfigurationId;
        this.proof = proofs;
        this.credentialResponseEncryption = credentialResponseEncryption;
    }

    public List<ProofJwt> getProofs(int acceptableProofTimeWindow, int nonceLifetimeSeconds) {

        if (proof == null || proof.isEmpty()) {
            return List.of();
        }

        var jwts = proof.get(ProofType.JWT.toString());

        try {
            return ((List<?>) jwts).stream().map(proofJwt -> new ProofJwt(ProofType.JWT,
                            (String) proofJwt, acceptableProofTimeWindow, nonceLifetimeSeconds))
                    .toList();
        } catch (Exception e) {
            throw new IllegalArgumentException("could not parse proof jwt(s) from credential request", e);
        }

    }
}