package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;

@Service
@AllArgsConstructor
public class HolderBindingService {

    private final IssuerMetadataTechnical issuerMetadata;
    private final OpenIdIssuerConfiguration openIDConfiguration;
    private final NonceService nonceService;
    private final KeyAttestationService keyAttestationService;

    public List<String> validateHolderPublicKeys(List<ProofJwt> holderPublicKeys,
                                                 CredentialOffer credentialOffer) throws Oid4vcException {

        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());
        Map<String, SupportedProofType> supportedProofTypes = credentialConfiguration.getProofTypesSupported();

        // If no proof types are supported, no holder binding is returned
        if (supportedProofTypes == null || supportedProofTypes.isEmpty()) {
            return List.of();
        }

        // check if proofs requested
        if (holderPublicKeys.isEmpty()) {
            throw new Oid4vcException(INVALID_PROOF, "Proof must be provided for the requested credential");
        }

        var batchCredentialIssuanceMetadata = issuerMetadata.getBatchCredentialIssuance();

        // check batch issuance
        if (batchCredentialIssuanceMetadata == null && holderPublicKeys.size() > 1) {
            throw new Oid4vcException(INVALID_PROOF, "Multiple proofs are not allowed for this credential request");
        }

        if (batchCredentialIssuanceMetadata != null && batchCredentialIssuanceMetadata.batchSize() < holderPublicKeys.size()) {
            throw new Oid4vcException(INVALID_PROOF, "The number of proofs exceeds the batch size limit");
        }

        var result = holderPublicKeys.stream()
                .map(pk -> validateHolderPublicKeyV2(Optional.of(pk), credentialOffer, supportedProofTypes))
                .toList();

        // check if proof is unique
        // todo move up once proof jwt is refactored
        if (holderPublicKeys.stream().map(ProofJwt::getBinding).distinct().count() != holderPublicKeys.size()) {
            throw new Oid4vcException(INVALID_PROOF, "Proofs should not be duplicated for the same credential request");
        }

        List<String> nonces = holderPublicKeys.stream()
                .map(ProofJwt::getNonce)
                .toList();

        invalidateSelfContainedNonce(nonces);

        return result;
    }

    /**
     * Validate and process the credentialRequest
     *
     * @param proofJwt        the proof JWT that contains the holder's public key
     * @param credentialOffer the credential offer for which the request was sent
     * @return the holder's public key or an empty optional
     * if for the offered credential no holder binding is required
     * @throws Oid4vcException if the credential request is invalid in some form
     */
    public Optional<String> getHolderPublicKey(Optional<ProofJwt> proofJwt,
                                               CredentialOffer credentialOffer) {
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        // Process Holder Binding if a Proof Type is required
        var supportedProofTypes = credentialConfiguration.getProofTypesSupported();
        if (supportedProofTypes != null && !supportedProofTypes.isEmpty()) {
            var requestProof = proofJwt.orElseThrow(() -> new Oid4vcException(INVALID_PROOF, "Proof must be provided for the requested credential"));
            var bindingProofType = Optional.of(supportedProofTypes.get(requestProof.getProofType().toString()))
                    .orElseThrow(() -> new Oid4vcException(INVALID_PROOF,
                            "Provided proof is not supported for the credential requested."));
            try {
                if (!requestProof.isValidHolderBinding(
                        (String) openIDConfiguration.getIssuerMetadata().get("credential_issuer"),
                        bindingProofType.getSupportedSigningAlgorithms(),
                        credentialOffer.getNonce(),
                        credentialOffer.getTokenExpirationTimestamp())) {
                    throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
                }
                var nonce = new SelfContainedNonce(requestProof.getNonce());
                if (nonce.isSelfContainedNonce()) {
                    if (nonceService.isUsedNonce(nonce)) {
                        throw new Oid4vcException(INVALID_PROOF, "Presented proof was reused!");
                    }
                    nonceService.registerNonce(nonce);
                }
            } catch (IOException e) {
                throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
            }

            keyAttestationService.checkHolderKeyAttestation(bindingProofType, requestProof);

            return Optional.of(requestProof.getBinding());
        }

        return Optional.empty();
    }

    public String validateHolderPublicKeyV2(Optional<ProofJwt> proofJwt,
                                            CredentialOffer credentialOffer,
                                            Map<String, SupportedProofType> supportedProofTypes) throws Oid4vcException {

        var requestProof = proofJwt.orElseThrow(() ->
                new Oid4vcException(INVALID_PROOF, "Proof must be provided for the requested credential"));

        var bindingProofType = supportedProofTypes.get(requestProof.getProofType().toString());

        if (bindingProofType == null) {
            throw new Oid4vcException(INVALID_PROOF, "Provided proof is not supported for the credential requested.");
        }

        try {
            if (!requestProof.isValidHolderBinding(
                    (String) openIDConfiguration.getIssuerMetadata().get("credential_issuer"),
                    bindingProofType.getSupportedSigningAlgorithms(),
                    credentialOffer.getNonce(),
                    credentialOffer.getTokenExpirationTimestamp())) {
                throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
            }
            var nonce = new SelfContainedNonce(requestProof.getNonce());

            if (nonce.isSelfContainedNonce() && nonceService.isUsedNonce(nonce)) {
                throw new Oid4vcException(INVALID_PROOF, "Presented proof was reused!");
            }

        } catch (IOException e) {
            throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
        }

        keyAttestationService.checkHolderKeyAttestation(bindingProofType, requestProof);

        return requestProof.getBinding();
    }

    private void invalidateSelfContainedNonce(List<String> nonces) {
        nonces.forEach(nonce -> {
            var selfContainedNonce = new SelfContainedNonce(nonce);
            if (selfContainedNonce.isSelfContainedNonce()) {
                nonceService.registerNonce(selfContainedNonce);
            }
        });
    }
}