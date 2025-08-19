package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

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
    private final ApplicationProperties applicationProperties;

    public List<ProofJwt> getValidateHolderPublicKeys(CredentialRequestClass credentialRequest,
                                                      CredentialOffer credentialOffer) throws Oid4vcException {

        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());
        Map<String, SupportedProofType> supportedProofTypes = credentialConfiguration.getProofTypesSupported();

        // If no proof types are supported, no holder binding is returned
        if (supportedProofTypes == null || supportedProofTypes.isEmpty()) {
            return List.of();
        }

        List<ProofJwt> proofs = credentialRequest.getProofs(
                applicationProperties.getAcceptableProofTimeWindowSeconds(),
                applicationProperties.getAcceptableProofTimeWindowSeconds());

        // check if proofs requested
        if (proofs.isEmpty()) {
            throw new Oid4vcException(INVALID_PROOF, "Proof must be provided for the requested credential");
        }

        var batchCredentialIssuanceMetadata = issuerMetadata.getBatchCredentialIssuance();

        // check batch issuance
        if (batchCredentialIssuanceMetadata == null && proofs.size() > 1) {
            throw new Oid4vcException(INVALID_PROOF, "Multiple proofs are not allowed for this credential request");
        }

        if (batchCredentialIssuanceMetadata != null && batchCredentialIssuanceMetadata.batchSize() < proofs.size()) {
            throw new Oid4vcException(INVALID_PROOF, "The number of proofs exceeds the batch size limit");
        }

        var proofJwts = proofs.stream()
                .map(pk -> validateHolderPublicKeyV2(Optional.of(pk), credentialOffer, supportedProofTypes))
                .toList();

        // check if proof is unique
        // todo move up once proof jwt is refactored
        if (proofs.stream().map(ProofJwt::getBinding).distinct().count() != proofs.size()) {
            throw new Oid4vcException(INVALID_PROOF, "Proofs should not be duplicated for the same credential request");
        }

        List<String> nonces = proofs.stream()
                .map(ProofJwt::getNonce)
                .toList();

        nonceService.invalidateSelfContainedNonce(nonces);

        return proofJwts;
    }

    /**
     * Validate and process the credentialRequest
     *
     * @param credentialRequest the credential request containing the holder's public key
     * @param credentialOffer   the credential offer for which the request was sent
     * @return the holder's public key or an empty optional
     * if for the offered credential no holder binding is required
     * @throws Oid4vcException if the credential request is invalid in some form
     */
    public Optional<ProofJwt> getHolderPublicKey(CredentialRequestClass credentialRequest,
                                                 CredentialOffer credentialOffer) {
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        // Process Holder Binding if a Proof Type is required
        var supportedProofTypes = credentialConfiguration.getProofTypesSupported();

        if (CollectionUtils.isEmpty(supportedProofTypes)) {
            return Optional.empty();
        }

        var proofsJwt = credentialRequest.getProofs(applicationProperties.getAcceptableProofTimeWindowSeconds(),
                applicationProperties.getAcceptableProofTimeWindowSeconds());

        if (CollectionUtils.isEmpty(proofsJwt) || proofsJwt.getFirst() == null) {
            throw new Oid4vcException(INVALID_PROOF, "Proof must be provided for the requested credential");
        }

        var requestProof = proofsJwt.getFirst();

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

        keyAttestationService.valdidateAndGetHolderKeyAttestation(bindingProofType, requestProof);

        return Optional.of(requestProof);
    }

    public ProofJwt validateHolderPublicKeyV2(Optional<ProofJwt> proofJwt,
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

        keyAttestationService.valdidateAndGetHolderKeyAttestation(bindingProofType, requestProof);

        return requestProof;
    }
}