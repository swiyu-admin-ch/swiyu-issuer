package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttestableProof;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttestationJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.Proof;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.text.ParseException;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;

@Service
@AllArgsConstructor
public class KeyAttestationService {
    private final KeyResolver keyResolver;
    private final ApplicationProperties applicationProperties;

    public String validateAndGetHolderKeyAttestation(SupportedProofType supportedProofType, Proof requestProof) throws Oid4vcException {

        if (supportedProofType == null) {
            return null;
        }

        var attestationRequirement = supportedProofType.getKeyAttestationRequirement();

        // No Attestation required, no further checks needed
        if (attestationRequirement == null) {
            return null;
        }

        return getAndValidateKeyAttestation(attestationRequirement, requestProof);
    }

    public String getAndValidateKeyAttestation(@NotNull KeyAttestationRequirement attestationRequirement, @NotNull Proof requestProof) throws Oid4vcException {

        // Proof type cannot hold an attestation
        if (!(requestProof instanceof AttestableProof)) {
            throw new Oid4vcException(INVALID_PROOF, "Attestation was requested, but presented proof is not attestable!",
                    Map.of(
                            "proofType", requestProof.getProofType() != null ? requestProof.getProofType().toString() : "null"
                    ));
        }

        var attestationJwt = ((AttestableProof) requestProof).getAttestationJwt();
        if (attestationJwt == null) {
            throw new Oid4vcException(INVALID_PROOF, "Attestation was not provided!",
                    Map.of(
                            "proofType", requestProof.getProofType() != null ? requestProof.getProofType().toString() : "null"
                    ));
        }

        AttestationJwt attestation = validateKeyAttestation(attestationRequirement, attestationJwt);
        verifyProofKeyInAttestedKeys(requestProof, attestation);

        try {
            return attestation.toJsonString();
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Key attestation is malformed!");
        }
    }

    /**
     * Validates a key attestation JWT and check if the supplied {@link KeyAttestationRequirement} is satisfied.
     * <br>
     *
     * @param attestationRequirement the requirement defining the expected key storage and
     *                               other attestation constraints
     * @param attestationJwt the raw JWT string to be validated
     * @return a fully parsed and validated {@link AttestationJwt}
     * @throws Oid4vcException if parsing fails, the JWT is malformed, the provider is not
     *                         trusted, validation against the requirement fails, or the
     *                         signature algorithm is unsupported
     */
    public AttestationJwt validateKeyAttestation(KeyAttestationRequirement attestationRequirement, String attestationJwt) {
        try {
            AttestationJwt attestation = AttestationJwt.parseJwt(attestationJwt, applicationProperties.isSwissProfileVersioningEnforcement());
            var trustedAttestationServices = applicationProperties.getTrustedAttestationProviders();

            // If trusted Attestation Services is empty, all attestation services are trusted for ease of trying out things.
            if (!trustedAttestationServices.isEmpty()) {
                attestation.throwIfNotTrustedAttestationProvider(trustedAttestationServices);
            }

            if (!attestation.isValidAttestation(keyResolver, attestationRequirement.getKeyStorage())) {
                throw new Oid4vcException(INVALID_PROOF, "Key attestation was invalid or not matching the attack resistance for the credential!");
            }
            
            return attestation;
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Key attestation is malformed!");
        } catch (IllegalArgumentException e) {
            throw new Oid4vcException(e, INVALID_PROOF, String.format("Attestation has been rejected! %s", e.getMessage()));
        } catch (JOSEException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Key attestation key is not supported or not matching the signature!");
        }
    }

    /**
     * Verifies that the proof binding key is included in the {@code attested_keys} of the given attestation.
     * This check closes the key-mismatch attack vector where a valid attestation for Key A is combined with
     * a proof signed by an unattested Key B.
     *
     * @param requestProof the validated proof whose binding key must appear in the attestation
     * @param attestation  the validated key attestation containing the attested key set
     * @throws Oid4vcException if the proof key is not listed in the attested keys or if key parsing fails
     */
    private void verifyProofKeyInAttestedKeys(@NotNull Proof requestProof, @NotNull AttestationJwt attestation) {
        var bindingJson = requestProof.getBinding();
        if (bindingJson == null) {
            throw new Oid4vcException(INVALID_PROOF, "Proof has no binding key – cannot verify against attested_keys");
        }

        ECKey proofKey = parseProofKey(bindingJson);
        verifyKeyPresentInAttestation(proofKey, attestation);
    }

    private ECKey parseProofKey(String bindingJson) {
        try {
            return ECKey.parse(bindingJson);
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Proof binding key could not be parsed for attested_keys verification!");
        }
    }


    /**
     * Verifies that the supplied {@code proofKey} is listed in the {@code attested_keys}
     * claim of the given {@link AttestationJwt}.
     *
     * @param proofKey    the EC key used as proof
     * @param attestation the attestation JWT containing the {@code attested_keys}
     * @throws Oid4vcException with {@code INVALID_PROOF} if the proof key does not
     *         match any key in the attestation or if thumb‑print computation fails
     */
    public void verifyKeyPresentInAttestation(ECKey proofKey, AttestationJwt attestation) {
        try {
            if (!attestation.containsKey(proofKey)) {
                throw new Oid4vcException(INVALID_PROOF,
                        "Proof key does not match any key listed in the attestation's attested_keys",
                        Map.of("proofKeyThumbprint", computeThumbprintSafe(proofKey)));
            }
        } catch (JOSEException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Proof key thumbprint computation failed during attested_keys verification!");
        }
    }

    private String computeThumbprintSafe(ECKey key) {
        try {
            return key.toPublicJWK().computeThumbprint().toString();
        } catch (JOSEException e) {
            return "unavailable";
        }
    }
}