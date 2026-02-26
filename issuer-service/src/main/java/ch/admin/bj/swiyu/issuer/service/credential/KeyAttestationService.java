package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttestableProof;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttestationJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.Proof;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import com.nimbusds.jose.JOSEException;
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

            return attestation.toJsonString();
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Key attestation is malformed!");
        } catch (IllegalArgumentException e) {
            throw new Oid4vcException(e, INVALID_PROOF, String.format("Attestation has been rejected! %s", e.getMessage()));
        } catch (JOSEException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Key attestation key is not supported or not matching the signature!");
        }
    }
}