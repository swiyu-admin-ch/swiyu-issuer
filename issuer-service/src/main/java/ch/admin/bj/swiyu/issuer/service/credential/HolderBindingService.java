package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.issuer.service.MetadataService;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_CREDENTIAL_REQUEST;
import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;

/**
 * Service for handling holder binding operations, including validation and processing of proofs
 * and holder public keys in the context of credential issuance. This service manages proof validation,
 * nonce handling, and ensures compliance with supported proof types and batch issuance constraints.
 */
@Service
@AllArgsConstructor
public class HolderBindingService {

    private final MetadataService metadataService;
    private final NonceService nonceService;
    private final KeyAttestationService keyAttestationService;
    private final ApplicationProperties applicationProperties;

    /**
     * Validates the holder public keys from the credential request and credential offer.
     * Handles proof extraction, validation, nonce management, and batch issuance constraints.
     *
     * @param credentialRequest the credential request containing proofs
     * @param credentialOffer   the credential offer for which the request was sent
     * @return a list of validated ProofJwt objects
     * @throws Oid4vcException if validation fails or proofs are invalid
     */
    public List<ProofJwt> getValidateHolderPublicKeys(CredentialRequestClass credentialRequest,
                                                      CredentialOffer credentialOffer) throws Oid4vcException {

        var issuerMetadata = getIssuerMetadata(credentialOffer.getMetadataTenantId());
        var supportedProofTypes = resolveSupportedProofTypes(credentialOffer);
        if (supportedProofTypes.isEmpty()) {
            return List.of();
        }

        List<ProofJwt> proofs = extractProofs(credentialRequest);
        validateProofsPresence(proofs);
        validateBatchIssuanceConstraints(proofs, issuerMetadata);

        var proofJwts = proofs.stream()
                .map(proof -> validateProof(proof, credentialOffer, supportedProofTypes, this::ensureNonceNotReused))
                .toList();

        ensureUniqueProofBindings(proofs);
        handleProofNonces(proofs, credentialOffer);

        return proofJwts;
    }

    /**
     * Validate and process the credentialRequest to extract the holder's public key.
     *
     * @param credentialRequest the credential request containing the holder's public key
     * @param credentialOffer   the credential offer for which the request was sent
     * @return an Optional containing the holder's public key if holder binding is required, otherwise empty
     * @throws Oid4vcException if the credential request is invalid in some form
     */
    public Optional<ProofJwt> getHolderPublicKey(CredentialRequestClass credentialRequest,
                                                 CredentialOffer credentialOffer) {

        var supportedProofTypes = resolveSupportedProofTypes(credentialOffer);
        if (supportedProofTypes.isEmpty()) {
            return Optional.empty();
        }

        var proofs = extractProofs(credentialRequest);
        var requestProof = selectFirstProof(proofs);

        return Optional.of(validateProof(requestProof, credentialOffer, supportedProofTypes, this::registerNonceIfNeeded));
    }


    private Map<String, SupportedProofType> resolveSupportedProofTypes(CredentialOffer credentialOffer) {
        var issuerMetadata = getIssuerMetadata(credentialOffer.getMetadataTenantId());
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst());
        return Optional.ofNullable(credentialConfiguration.getProofTypesSupported())
                .orElse(Map.of());
    }

    private List<ProofJwt> extractProofs(CredentialRequestClass credentialRequest) throws Oid4vcException {
        try {
            return credentialRequest.getProofs(
                    applicationProperties.getAcceptableProofTimeWindowSeconds(),
                    applicationProperties.getAcceptableProofTimeWindowSeconds());
        } catch (IllegalArgumentException e) {
            throw new Oid4vcException(e, INVALID_CREDENTIAL_REQUEST, "Invalid proof");
        }
    }

    private void validateProofsPresence(List<ProofJwt> proofs) throws Oid4vcException {
        if (CollectionUtils.isEmpty(proofs)) {
            throw new Oid4vcException(INVALID_PROOF, "Proof must be provided for the requested credential");
        }
    }

    private void validateBatchIssuanceConstraints(List<ProofJwt> proofs, IssuerMetadata issuerMetadata) throws Oid4vcException {
        var batchCredentialIssuanceMetadata = issuerMetadata.getBatchCredentialIssuance();
        if (batchCredentialIssuanceMetadata == null && proofs.size() > 1) {
            throw new Oid4vcException(INVALID_PROOF, "Multiple proofs are not allowed for this credential request");
        }
        if (batchCredentialIssuanceMetadata != null && batchCredentialIssuanceMetadata.batchSize() < proofs.size()) {
            throw new Oid4vcException(INVALID_PROOF, "The number of proofs must match the batch size");
        }
    }

    private void ensureUniqueProofBindings(List<ProofJwt> proofs) throws Oid4vcException {
        if (proofs.stream()
                .map(ProofJwt::getBinding)
                .distinct()
                .count() != proofs.size()) {
            throw new Oid4vcException(INVALID_PROOF, "Proofs should not be duplicated for the same credential request");
        }
    }

    private void handleProofNonces(List<ProofJwt> proofs, CredentialOffer credentialOffer) {
        List<String> nonces = proofs.stream()
                .map(ProofJwt::getNonce)
                .toList();
        nonceService.invalidateSelfContainedNonce(nonces);
        credentialOffer.setNonce(UUID.randomUUID()); // Change c_nonce value
    }

    private ProofJwt selectFirstProof(List<ProofJwt> proofs) throws Oid4vcException {
        validateProofsPresence(proofs);
        return proofs.getFirst();
    }

    private SupportedProofType resolveBindingProofType(ProofJwt requestProof,
                                                       Map<String, SupportedProofType> supportedProofTypes) throws
            Oid4vcException {
        return Optional.ofNullable(supportedProofTypes.get(requestProof.getProofType().toString()))
                .orElseThrow(() -> new Oid4vcException(INVALID_PROOF,
                        "Provided proof is not supported for the credential requested."));
    }


    private void validateHolderBinding(ProofJwt requestProof, SupportedProofType bindingProofType,
                                       CredentialOffer credentialOffer) throws Oid4vcException {
        var mgmt = credentialOffer.getCredentialManagement();
        var issuerMetadata = getIssuerMetadata(credentialOffer.getMetadataTenantId());
        if (!requestProof.isValidHolderBinding(
                issuerMetadata.getCredentialIssuer(),
                bindingProofType.getSupportedSigningAlgorithms(),
                credentialOffer.getNonce(),
                mgmt.getAccessTokenExpirationTimestamp())) {
            throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
        }
    }

    private void ensureNonceNotReused(ProofJwt requestProof) throws Oid4vcException {
        var nonce = new SelfContainedNonce(requestProof.getNonce());
        if (nonce.isSelfContainedNonce() && nonceService.isUsedNonce(nonce)) {
            throw new Oid4vcException(INVALID_PROOF, "Presented proof was reused!");
        }
    }

    private void registerNonceIfNeeded(ProofJwt requestProof) throws Oid4vcException {
        var nonce = new SelfContainedNonce(requestProof.getNonce());
        if (nonce.isSelfContainedNonce()) {
            if (nonceService.isUsedNonce(nonce)) {
                throw new Oid4vcException(INVALID_PROOF, "Presented proof was reused!");
            }
            nonceService.registerNonce(nonce);
        }
    }

    /**
     * Validates a single proof against the credential offer and supported proof types, applying the provided nonce handler.
     *
     * @param requestProof        the proof to validate
     * @param credentialOffer     the credential offer for which the request was sent
     * @param supportedProofTypes the supported proof types for the credential
     * @param nonceHandler        the handler to apply for nonce validation/registration
     * @return the validated ProofJwt
     * @throws Oid4vcException if validation fails or the proof is invalid
     */
    ProofJwt validateProof(ProofJwt requestProof, CredentialOffer credentialOffer,
                           Map<String, SupportedProofType> supportedProofTypes,
                           NonceHandler nonceHandler) throws Oid4vcException {

        var bindingProofType = resolveBindingProofType(requestProof, supportedProofTypes);
        validateHolderBinding(requestProof, bindingProofType, credentialOffer);
        nonceHandler.apply(requestProof);
        keyAttestationService.validateAndGetHolderKeyAttestation(bindingProofType, requestProof);

        return requestProof;
    }

    private IssuerMetadata getIssuerMetadata(UUID tenantId) {
        if (applicationProperties.isSignedMetadataEnabled()) {
            return metadataService.getUnsignedIssuerMetadata(tenantId);
        }
        return metadataService.getUnsignedIssuerMetadata();
    }

    @FunctionalInterface
    private interface NonceHandler {
        void apply(ProofJwt proof) throws Oid4vcException;
    }
}