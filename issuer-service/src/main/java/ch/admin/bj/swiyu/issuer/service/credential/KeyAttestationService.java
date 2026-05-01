package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.didresolveradapter.DidResolverAdapter;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttestableProof;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttestationJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.Proof;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Map;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;

/**
 * Service responsible for validating key attestation JWTs presented during credential issuance.
 *
 * <p>Signature verification is performed via {@link DidJwtValidator} (Flow B, two-step):
 * the DID URL is validated against the Base Registry allowlist before the DID Document is
 * fetched and the signature is cryptographically verified.</p>
 */
@Service
@AllArgsConstructor
public class KeyAttestationService {

    private final DidJwtValidator didJwtValidator;
    private final DidResolverAdapter didResolverAdapter;
    private final UrlRewriteProperties urlRewriteProperties;
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
     * Validates a key attestation JWT and checks if the supplied {@link KeyAttestationRequirement} is satisfied.
     *
     * <p>Validation steps:</p>
     * <ol>
     *   <li>Validate the DID URL against the Base Registry allowlist (via {@link DidJwtValidator#getAndValidateResolutionUrl}).</li>
     *   <li>Resolve the DID Document via {@link DidResolverAdapter}.</li>
     *   <li>Verify the JWT signature against the DID Document.</li>
     *   <li>Check structural attestation rules (trusted provider, attack potential resistance).</li>
     * </ol>
     *
     * @param attestationRequirement the requirement defining the expected key storage and
     *                               other attestation constraints
     * @param attestationJwt         the raw JWT string to be validated
     * @return a fully parsed and validated {@link AttestationJwt}
     * @throws Oid4vcException if any validation step fails
     */
    public AttestationJwt validateKeyAttestation(KeyAttestationRequirement attestationRequirement, String attestationJwt) {
        try {
            // Step 1: validate DID URL format + Base Registry allowlist
            didJwtValidator.getAndValidateResolutionUrl(attestationJwt);

            // Step 2: resolve DID document using the new convenience method
            var did = didJwtValidator.getDidString(attestationJwt);
            try (var didDoc = didResolverAdapter.resolveDid(did, urlRewriteProperties.getUrlMappings())) {
                // Step 3: verify signature
                didJwtValidator.validateJwt(attestationJwt, didDoc);
            }

            // Step 4: domain-level validation
            AttestationJwt attestation = AttestationJwt.parseJwt(attestationJwt, applicationProperties.isSwissProfileVersioningEnforcement());
            var trustedAttestationServices = applicationProperties.getTrustedAttestationProviders();
            attestation.throwIfNotTrustedAttestationProvider(trustedAttestationServices);

            if (!attestation.isValidAttestation(attestationRequirement.getKeyStorage())) {
                throw new Oid4vcException(INVALID_PROOF, "Key attestation was invalid or not matching the attack resistance for the credential!");
            }

            return attestation;
        } catch (JwtValidatorException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Key attestation DID validation failed: " + e.getMessage());
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Key attestation is malformed!");
        } catch (IllegalArgumentException e) {
            throw new Oid4vcException(e, INVALID_PROOF, String.format("Attestation has been rejected! %s", e.getMessage()));
        } catch (Exception e) {
            throw new Oid4vcException(INVALID_PROOF, "Key attestation validation failed: " + e.getMessage());
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