package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.Proof;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;

@Service
@AllArgsConstructor
public class HolderBindingService {

    private final IssuerMetadataTechnical issuerMetadata;
    private final ApplicationProperties applicationProperties;
    private final OpenIdIssuerConfiguration openIDConfiguration;
    private final NonceService nonceService;
    private final KeyAttestationService keyAttestationService;

    public List<String> getHolderPublicKeys(CredentialRequestClass credentialRequest,
                                            CredentialOffer credentialOffer) {

        var proofs = credentialRequest.getProofs(
                applicationProperties.getAcceptableProofTimeWindowSeconds(),
                applicationProperties.getAcceptableProofTimeWindowSeconds());

        // Validate and process the credential request
        return proofs.stream()
                .map(proof -> getHolderPublicKey(proof, credentialOffer))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .toList();
    }

    /**
     * Validate and process the credentialRequest
     *
     * @param credentialRequest the credential request to be processed
     * @param credentialOffer   the credential offer for which the request was sent
     * @return the holder's public key or an empty optional
     * if for the offered credential no holder binding is required
     * @throws Oid4vcException if the credential request is invalid in some form
     */
    public Optional<String> getHolderPublicKey(CredentialRequestClass credentialRequest,
                                               CredentialOffer credentialOffer) {
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        // Process Holder Binding if a Proof Type is required
        var supportedProofTypes = credentialConfiguration.getProofTypesSupported();
        if (supportedProofTypes != null && !supportedProofTypes.isEmpty()) {
            var requestProof = credentialRequest.getProof(applicationProperties.getAcceptableProofTimeWindowSeconds(), applicationProperties.getAcceptableProofTimeWindowSeconds())
                    .orElseThrow(
                            () -> new Oid4vcException(INVALID_PROOF,
                                    "Proof must be provided for the requested credential"));
            var bindingProofType = Optional.of(supportedProofTypes.get(requestProof.proofType.toString()))
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

    private Optional<String> getHolderPublicKey(Proof proof,
                                                CredentialOffer credentialOffer) {
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        // Process Holder Binding if a Proof Type is required
        var supportedProofTypes = credentialConfiguration.getProofTypesSupported();
        if (supportedProofTypes != null && !supportedProofTypes.isEmpty()) {
//            var requestProof = credentialRequest.getProof(applicationProperties.getAcceptableProofTimeWindowSeconds(), applicationProperties.getAcceptableProofTimeWindowSeconds())
//                    .orElseThrow(
//                            () -> new Oid4vcException(INVALID_PROOF,
//                                    "Proof must be provided for the requested credential"));
            if (proof == null) {
                throw new Oid4vcException(INVALID_PROOF, "Proof must be provided for the requested credential");
            }

            var bindingProofType = Optional.of(supportedProofTypes.get(proof.proofType.toString()))
                    .orElseThrow(() -> new Oid4vcException(INVALID_PROOF,
                            "Provided proof is not supported for the credential requested."));
            try {
                if (!proof.isValidHolderBinding(
                        (String) openIDConfiguration.getIssuerMetadata().get("credential_issuer"),
                        bindingProofType.getSupportedSigningAlgorithms(),
                        credentialOffer.getNonce(),
                        credentialOffer.getTokenExpirationTimestamp())) {
                    throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
                }
                var nonce = new SelfContainedNonce(proof.getNonce());
                if (nonce.isSelfContainedNonce()) {
                    if (nonceService.isUsedNonce(nonce)) {
                        throw new Oid4vcException(INVALID_PROOF, "Presented proof was reused!");
                    }
                    nonceService.registerNonce(nonce);
                }
            } catch (IOException e) {
                throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
            }

            keyAttestationService.checkHolderKeyAttestation(bindingProofType, proof);

            return Optional.of(proof.getBinding());
        }

        return Optional.empty();
    }
}