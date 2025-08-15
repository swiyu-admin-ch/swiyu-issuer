package ch.admin.bj.swiyu.issuer.service;

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
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;

@Service
@AllArgsConstructor
public class KeyAttestationService {
    private final KeyResolver keyResolver;
    private final ApplicationProperties applicationProperties;

    public String checkHolderKeyAttestation(SupportedProofType supportedProofType, Proof requestProof) throws Oid4vcException {

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

    public List<String> checkHolderKeyAttestation(SupportedProofType supportedProofType, List<Proof> requestProofs) throws Oid4vcException {

        List<String> attestations = new ArrayList<>();
        // check if proof type is requested
        if (supportedProofType == null) {
            return attestations;
        }

        var attestationRequirement = supportedProofType.getKeyAttestationRequirement();

        // if attestation is not required, no further checks needed
        if (attestationRequirement == null) {
            return attestations;
        }

        // check if any proofs provided
        if (CollectionUtils.isEmpty(requestProofs)) {
            return List.of();
        }

        // get and validate key attestations for each proof
        return requestProofs.stream().map(
                proof -> {
                    try {
                        return getAndValidateKeyAttestation(attestationRequirement, proof);
                    } catch (Oid4vcException e) {
                        // If one attestation is invalid, we throw an exception
                        throw new Oid4vcException(e, INVALID_PROOF, "Key attestation is invalid for one of the proofs!");
                    }
                }
        ).toList();
    }

    public String getAndValidateKeyAttestation(@NotNull KeyAttestationRequirement attestationRequirement, @NotNull Proof requestProof) throws Oid4vcException {

        // Proof type cannot hold an attestation
        if (!(requestProof instanceof AttestableProof)) {
            throw new Oid4vcException(INVALID_PROOF, "Attestation was requested, but presented proof is not attestable!");
        }

        var attestationJwt = ((AttestableProof) requestProof).getAttestationJwt();
        if (attestationJwt == null) {
            throw new Oid4vcException(INVALID_PROOF, "Attestation was not provided!");
        }

        try {
            AttestationJwt attestation = AttestationJwt.parseJwt(attestationJwt);
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