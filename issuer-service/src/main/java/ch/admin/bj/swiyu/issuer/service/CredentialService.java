/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.*;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialRequestDtoV2;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.*;
import static ch.admin.bj.swiyu.issuer.service.mapper.CredentialRequestMapper.toCredentialRequest;
import static java.util.Objects.isNull;

@Slf4j
@Service
@AllArgsConstructor
public class CredentialService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final ObjectMapper objectMapper;
    private final IssuerMetadataTechnical issuerMetadata;
    private final CredentialFormatFactory vcFormatFactory;
    private final ApplicationProperties applicationProperties;
    private final WebhookService webhookService;
    private final OpenIdIssuerConfiguration openIDConfiguration;
    private final NonceService nonceService;
    private final KeyAttestationService keyAttestationService;

    @Transactional
    public CredentialEnvelopeDto createCredential(CredentialRequestDto credentialRequestDto, String accessToken,
                                                  ClientAgentInfo clientInfo) {

        CredentialRequestClass credentialRequest = toCredentialRequest(credentialRequestDto);
        CredentialOffer credentialOffer = getCredentialOfferByAccessToken(accessToken);

        return createCredentialEnvelopeDto(credentialOffer, credentialRequest, clientInfo);
    }

    @Transactional
    public CredentialEnvelopeDto createCredentialV2(CredentialRequestDtoV2 credentialRequestDto, String accessToken,
                                                    ClientAgentInfo clientInfo) {

        CredentialRequestClass credentialRequest = toCredentialRequest(credentialRequestDto);
        CredentialOffer credentialOffer = getCredentialOfferByAccessToken(accessToken);

        return createCredentialEnvelopeDto(credentialOffer, credentialRequest, clientInfo);
    }

    @Transactional
    public CredentialEnvelopeDto createCredentialFromDeferredRequest(
            DeferredCredentialRequestDto deferredCredentialRequest,
            String accessToken) {
        CredentialOffer credentialOffer = getCredentialOfferByTransactionIdAndAccessToken(
                deferredCredentialRequest.transactionId(),
                accessToken);

        // We have to check again that the Credential Status has not been changed to
        // catch race condition between holder & issuer
        if (credentialOffer.getCredentialStatus() != CredentialStatusType.READY) {
            throw new Oid4vcException(ISSUANCE_PENDING, "The credential is not marked as ready to be issued");
        }

        if (credentialOffer.hasTokenExpirationPassed()) {
            log.info("Received AccessToken for deferred credential offer {} was expired.", credentialOffer.getId());
            webhookService.produceErrorEvent(credentialOffer.getId(),
                    CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED,
                    "AccessToken expired, offer is stuck in READY");
            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        var credentialRequest = credentialOffer.getCredentialRequest();

        if (isNull(credentialRequest)) {
            throw new IllegalArgumentException("Credential Request is missing");
        }

        // Get holder public key which was stored in the credential request
        Optional<String> holderJWK = credentialOffer.getHolderJWKs() != null ? Optional.of(credentialOffer.getHolderJWKs().getFirst()) : Optional.empty();

        CredentialEnvelopeDto vc = vcFormatFactory
                // get first entry because we expect the list to only contain one item
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .holderBinding(holderJWK)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredential();

        credentialOffer.markAsIssued();

        credentialOfferRepository.save(credentialOffer);
        webhookService.produceStateChangeEvent(credentialOffer.getId(), credentialOffer.getCredentialStatus());

        return vc;
    }

    /**
     * Issues an OAuth token for a given pre-authorization code created by issuer
     * mgmt
     *
     * @param preAuthCode Pre-authorization code of holder
     * @return OAuth authorization token which can be used in credential service
     * endpoint
     */
    @Transactional
    public OAuthTokenDto issueOAuthToken(String preAuthCode) {
        var offer = getCredentialOfferByPreAuthCode(preAuthCode);

        if (offer.getCredentialStatus() != CredentialStatusType.OFFERED) {
            log.debug("Refused to issue OAuth token. Credential offer {} has already state {}.", offer.getId(),
                    offer.getCredentialStatus());
            throw OAuthException.invalidGrant("Credential has already been used");
        }
        log.info("Pre-Authorized code consumed, sending Access Token {}. Management ID is {} and new status is {}",
                offer.getAccessToken(), offer.getId(), offer.getCredentialStatus());
        offer.markAsInProgress();
        offer.setTokenIssuanceTimestamp(applicationProperties.getTokenTTL());

        credentialOfferRepository.save(offer);
        webhookService.produceStateChangeEvent(offer.getId(), offer.getCredentialStatus());

        return OAuthTokenDto.builder()
                .accessToken(offer.getAccessToken().toString())
                .expiresIn(applicationProperties.getTokenTTL())
                .cNonce(offer.getNonce().toString())
                .build();
    }

    private CredentialEnvelopeDto createCredentialEnvelopeDto(CredentialOffer credentialOffer, CredentialRequestClass credentialRequest, ClientAgentInfo clientInfo) {
        // We have to check again that the Credential Status has not been changed to
        // catch race condition between holder & issuer
        if (!credentialOffer.getCredentialStatus().equals(CredentialStatusType.IN_PROGRESS)) {
            log.info("Credential offer {} failed to create VC, as state was not IN_PROGRESS instead was {}",
                    credentialOffer.getId(), credentialOffer.getCredentialStatus());
            throw OAuthException.invalidGrant(String.format(
                    "Offer is not valid anymore. The current offer state is %s." +
                            "The user should probably contact the business issuer about this.",
                    credentialOffer.getCredentialStatus()));
        }

        if (credentialOffer.hasTokenExpirationPassed()) {
            log.info("Received AccessToken for credential offer {} was expired.", credentialOffer.getId());
            webhookService.produceErrorEvent(credentialOffer.getId(),
                    CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED,
                    "AccessToken expired, offer possibly stuck in IN_PROGRESS");
            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        if (!credentialConfiguration.getFormat().equals(credentialRequest.getFormat())) {
            // This should only occur when the wallet has a bug
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_FORMAT, "Mismatch between requested and offered format.");
        }


        if (credentialRequest.getCredentialConfigurationId() != null && credentialOffer.getMetadataCredentialSupportedId().getFirst().equals(credentialRequest.getCredentialConfigurationId())) {
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_TYPE, "Mismatch between requested and offered credential configuration id.");
        }

        var proofsJwt = credentialRequest.getProofs(applicationProperties.getAcceptableProofTimeWindowSeconds(), applicationProperties.getAcceptableProofTimeWindowSeconds());
        Optional<ProofJwt> proofJwt = proofsJwt.isEmpty() ? Optional.empty() : Optional.of(proofsJwt.getFirst());

        Optional<String> holderPublicKey;
        try {
            holderPublicKey = getHolderPublicKey(proofJwt, credentialOffer);
        } catch (Oid4vcException e) {
            webhookService.produceErrorEvent(credentialOffer.getId(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR,
                    e.getMessage());
            throw e;
        }

        var vcBuilder = vcFormatFactory
                // get first entry because we expect the list to only contain one item
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .holderBinding(holderPublicKey)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId());

        CredentialEnvelopeDto responseEnvelope;

        // for deferred check if flag in the metadata set
        if (credentialOffer.isDeferred()) {
            var deferredData = new DeferredDataDto(UUID.randomUUID());

            responseEnvelope = vcBuilder.buildEnvelopeDto(deferredData);
            credentialOffer.markAsDeferred(deferredData.transactionId(), credentialRequest,
                    holderPublicKey.map(List::of).orElseGet(List::of), clientInfo);
            credentialOfferRepository.save(credentialOffer);
            try {
                var clientInfoString = objectMapper.writeValueAsString(clientInfo);
                webhookService.produceDeferredEvent(credentialOffer.getId(), clientInfoString);
            } catch (JsonProcessingException e) {
                throw new JsonException("Error processing client info for deferred credential offer", e);
            }
        } else {
            responseEnvelope = vcBuilder.buildCredential();
            credentialOffer.markAsIssued();
            credentialOfferRepository.save(credentialOffer);
            webhookService.produceStateChangeEvent(credentialOffer.getId(), credentialOffer.getCredentialStatus());
        }

        return responseEnvelope;
    }

    private Optional<CredentialOffer> getNonExpiredCredentialOffer(Optional<CredentialOffer> credentialOffer) {
        return credentialOffer
                .map(offer -> {
                    if (offer.getCredentialStatus() != CredentialStatusType.EXPIRED
                            && offer.hasExpirationTimeStampPassed()) {
                        offer.markAsExpired();
                        return credentialOfferRepository.save(offer);
                    }
                    return offer;
                });
    }

    private CredentialOffer getCredentialOfferByAccessToken(String accessToken) {
        var uuid = uuidOrException(accessToken);
        return getNonExpiredCredentialOffer(credentialOfferRepository.findByAccessToken(uuid))
                .orElseThrow(() -> OAuthException.invalidToken("Invalid accessToken"));
    }

    private CredentialOffer getCredentialOfferByTransactionIdAndAccessToken(UUID transactionId, String accessToken) {
        var credentialOffer = this.getCredentialOfferByAccessToken(accessToken);
        var storedTransactionId = credentialOffer.getTransactionId();

        if (isNull(storedTransactionId) || !storedTransactionId.equals(transactionId)) {
            throw new Oid4vcException(INVALID_TRANSACTION_ID, "Invalid transactional id");
        }

        return credentialOffer;
    }

    private CredentialOffer getCredentialOfferByPreAuthCode(String preAuthCode) {
        var uuid = uuidOrException(preAuthCode);
        return getNonExpiredCredentialOffer(credentialOfferRepository.findByPreAuthorizedCode(uuid))
                .orElseThrow(() -> OAuthException.invalidGrant("Invalid preAuthCode"));
    }

    private UUID uuidOrException(String preAuthCode) {
        UUID offerId;
        try {
            offerId = UUID.fromString(preAuthCode);
        } catch (IllegalArgumentException ex) {
            throw OAuthException.invalidRequest("Expecting a correct UUID");
        }
        return offerId;
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
    private Optional<String> getHolderPublicKey(Optional<ProofJwt> proofJwt,
                                                CredentialOffer credentialOffer) {
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        // Process Holder Binding if a Proof Type is required
        var supportedProofTypes = credentialConfiguration.getProofTypesSupported();
        if (supportedProofTypes != null && !supportedProofTypes.isEmpty()) {
            var requestProof = proofJwt.orElseThrow(() -> new Oid4vcException(INVALID_PROOF, "Proof must be provided for the requested credential"));
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
}