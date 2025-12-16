/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredCredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointRequestDtoV2;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.common.exception.RenewalException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.renewal.BusinessIssuerRenewalApiClient;
import ch.admin.bj.swiyu.issuer.service.renewal.RenewalRequestDto;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
    private final IssuerMetadata issuerMetadata;
    private final CredentialFormatFactory vcFormatFactory;
    private final ApplicationProperties applicationProperties;
    private final HolderBindingService holderBindingService;
    private final OAuthService oAuthService;
    private final EventProducerService eventProducerService;
    private final EncryptionService encryptionService;
    private final CredentialManagementRepository credentialManagementRepository;
    private final BusinessIssuerRenewalApiClient renewalApiClient;
    private final CredentialManagementService credentialManagementService;

    @Deprecated(since = "OID4VCI 1.0")
    @Transactional
    public CredentialEnvelopeDto createCredential(CredentialEndpointRequestDto credentialRequestDto,
                                                  String accessToken,
                                                  ClientAgentInfo clientInfo) {

        CredentialRequestClass credentialRequest = toCredentialRequest(credentialRequestDto);
        CredentialManagement mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        var credentialOffer = getFirstOffersInProgressAndCheckIfAnyOfferExpiredAndUpdate(mgmt)
                .orElseThrow(() -> OAuthException.invalidGrant(
                        "Invalid accessToken"));

        return createCredentialEnvelopeDto(credentialOffer, credentialRequest, clientInfo);
    }

    @Transactional
    public CredentialEnvelopeDto createCredentialV2(CredentialEndpointRequestDtoV2 credentialRequestDto,
                                                    String accessToken,
                                                    ClientAgentInfo clientInfo, String dpopKey) {

        var credentialRequest = toCredentialRequest(credentialRequestDto);
        var mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        var credentialOffer = getFirstOffersInProgressAndCheckIfAnyOfferExpiredAndUpdate(mgmt);

        // normal issuance flow
        if (credentialOffer.isPresent()) {
            return createCredentialEnvelopeDtoV2(credentialOffer.get(), credentialRequest, clientInfo, mgmt);
        }

        // renewal flow
        if (!applicationProperties.isRenewalFlowEnabled()) {
            log.info("Tried to renew credential for management id %s".formatted(mgmt.getId()));
            throw new RenewalException(HttpStatus.BAD_REQUEST, "No active offer found for %s and no renewal possible");
        }

        // check if dpop present
        if (dpopKey == null) {
            throw OAuthException.invalidGrant("Invalid accessToken - no DPoP key present for refresh flow");
        }

        // check if issued credential exists for the management
        var requestedCredentialOffers = mgmt.getCredentialOffers().stream()
                .filter(offer -> offer.getCredentialStatus() == CredentialOfferStatusType.REQUESTED).toList();

        if (!requestedCredentialOffers.isEmpty()) {
            throw new RenewalException(HttpStatus.TOO_MANY_REQUESTS, "Request already in progress");
        }

        var initialCredentialOfferForRenewal = this.credentialManagementService.createInitialCredentialOfferForRenewal(mgmt);

        var renewalData = new RenewalRequestDto(mgmt.getId(), initialCredentialOfferForRenewal.getId(), dpopKey);

        var renewedDataResponse = renewalApiClient.getRenewalData(renewalData);

        var offer = this.credentialManagementService.updateOfferFromRenewalResponse(renewedDataResponse, initialCredentialOfferForRenewal);

        return createCredentialEnvelopeDtoV2(offer, credentialRequest, clientInfo, mgmt);
    }

    @Deprecated(since = "OID4VCI 1.0")
    @Transactional
    public CredentialEnvelopeDto createCredentialFromDeferredRequest(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        CredentialOffer credentialOffer = getAndValidateCredentialOfferForDeferred(deferredCredentialRequest,
                accessToken);

        CredentialManagement mgmt = credentialOffer.getCredentialManagement();

        var credentialRequest = credentialOffer.getCredentialRequest();

        CredentialEnvelopeDto vc = vcFormatFactory
                // get first entry because we expect the list to only contain one item
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(credentialOffer.getHolderJWKs())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        credentialOffer.markAsIssued();
        mgmt.markAsIssued();

        credentialOfferRepository.save(credentialOffer);
        credentialManagementRepository.save(mgmt);

        eventProducerService.produceOfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());

        return vc;
    }

    @Transactional
    public CredentialEnvelopeDto createCredentialFromDeferredRequestV2(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        CredentialOffer credentialOffer = getAndValidateCredentialOfferForDeferred(deferredCredentialRequest,
                accessToken);

        CredentialManagement credentialMgmt = credentialOffer.getCredentialManagement();

        var credentialRequest = credentialOffer.getCredentialRequest();

        CredentialEnvelopeDto vc = vcFormatFactory
                // get first entry because we expect the list to only contain one item
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(credentialOffer.getHolderJWKs())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelopeV2();

        credentialOffer.markAsIssued();
        credentialMgmt.markAsIssued();

        credentialOfferRepository.save(credentialOffer);
        credentialManagementRepository.save(credentialMgmt);

        eventProducerService.produceOfferStateChangeEvent(credentialMgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());

        return vc;
    }

    private CredentialOffer getAndValidateCredentialOfferForDeferred(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        // check if offer exists and matches with access token -> transaction id is removed when issued
        CredentialOffer credentialOffer = getCredentialOfferByTransactionIdAndAccessToken(
                deferredCredentialRequest.transactionId(),
                accessToken);

        CredentialManagement mgmt = credentialOffer.getCredentialManagement();

        // check if credential can still be issued -> throws exception if [EXPIRED, CANCELLED]
        if (!credentialOffer.isProcessableOffer()) {
            throw new Oid4vcException(CREDENTIAL_REQUEST_DENIED,
                    "The credential can not be issued anymore, the offer was either cancelled or expired");
        }

        // We have to check again that the Credential Status has not been changed to
        // catch race condition between holder & issuer
        if (credentialOffer.getCredentialStatus() != CredentialOfferStatusType.READY) {
            throw new Oid4vcException(ISSUANCE_PENDING, "The credential is not marked as ready to be issued");
        }

        if (mgmt.hasTokenExpirationPassed()) {
            log.info("Received AccessToken for deferred credential offer {} was expired.", credentialOffer.getId());

            eventProducerService.produceErrorEvent("AccessToken expired, offer is stuck in READY",
                    CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED,
                    credentialOffer);

            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        if (isNull(credentialOffer.getCredentialRequest())) {
            throw new IllegalArgumentException("Credential Request is missing");
        }

        return credentialOffer;
    }

    @Deprecated(since = "OID4VCI 1.0")
    private CredentialEnvelopeDto createCredentialEnvelopeDto(CredentialOffer credentialOffer,
                                                              CredentialRequestClass credentialRequest,
                                                              ClientAgentInfo clientInfo) {
        // We have to check again that the Credential Status has not been changed to
        // catch race condition between holder & issuer
        validateCredentialRequest(credentialOffer, credentialRequest);

        var mgmt = credentialOffer.getCredentialManagement();

        Optional<ProofJwt> holderPublicKey;
        try {
            holderPublicKey = holderBindingService.getHolderPublicKey(credentialRequest, credentialOffer);
        } catch (Oid4vcException e) {

            eventProducerService.produceErrorEvent(e.getMessage(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, credentialOffer);

            throw e;
        }

        List<String> holderPublicKeyJwkList = holderPublicKey
                .map(ProofJwt::getBinding)
                .map(List::of)
                .orElseGet(List::of);

        List<String> keyAttestationJwkList = holderPublicKey
                .map(ProofJwt::getAttestationJwt)
                .map(List::of)
                .orElseGet(List::of);

        var vcBuilder = vcFormatFactory
                // get first entry because we expect the list to only contain one item
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(holderPublicKeyJwkList)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId());

        CredentialEnvelopeDto responseEnvelope;

        // for deferred check if flag in the metadata set
        if (credentialOffer.isDeferredOffer()) {
            var transactionId = UUID.randomUUID();

            responseEnvelope = vcBuilder.buildDeferredCredential(transactionId);
            credentialOffer.markAsDeferred(transactionId,
                    credentialRequest,
                    holderPublicKeyJwkList,
                    keyAttestationJwkList,
                    clientInfo,
                    applicationProperties);
            credentialOfferRepository.save(credentialOffer);
            eventProducerService.produceDeferredEvent(credentialOffer, clientInfo);
        } else {
            responseEnvelope = vcBuilder.buildCredentialEnvelope();
            credentialOffer.markAsIssued();
            credentialOfferRepository.save(credentialOffer);

            mgmt.markAsIssued();
            credentialManagementRepository.save(mgmt);
            eventProducerService.produceOfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());
        }

        return responseEnvelope;
    }


    private CredentialEnvelopeDto createCredentialEnvelopeDtoV2(CredentialOffer credentialOffer,
                                                                CredentialRequestClass credentialRequest,
                                                                ClientAgentInfo clientInfo, CredentialManagement mgmt) {
        validateCredentialRequest(credentialOffer, credentialRequest);

        List<ProofJwt> holderJwkList;
        try {
            holderJwkList = holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer);
        } catch (Oid4vcException e) {
            eventProducerService.produceErrorEvent(e.getMessage(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, credentialOffer);
            throw e;
        }

        List<String> holderPublicKeyJwkList = holderJwkList.stream()
                .map(ProofJwt::getBinding)
                .toList();

        var vcBuilder = vcFormatFactory
                // get first entry because we expect the list to only contain one item at the
                // moment
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(holderPublicKeyJwkList)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId());

        CredentialEnvelopeDto responseEnvelope;

        if (credentialOffer.isDeferredOffer()) {
            var transactionId = UUID.randomUUID();

            List<String> keyAttestationJwkList = holderJwkList.stream()
                    .map(ProofJwt::getAttestationJwt)
                    .toList();

            responseEnvelope = vcBuilder.buildDeferredCredentialV2(transactionId);
            credentialOffer.markAsDeferred(transactionId,
                    credentialRequest,
                    holderPublicKeyJwkList,
                    keyAttestationJwkList,
                    clientInfo,
                    applicationProperties);
            credentialOfferRepository.save(credentialOffer);
            eventProducerService.produceDeferredEvent(credentialOffer, clientInfo);
        } else {
            responseEnvelope = vcBuilder.buildCredentialEnvelopeV2();
            credentialOffer.markAsIssued();
            mgmt.markAsIssued();
            credentialOfferRepository.save(credentialOffer);
            credentialManagementRepository.save(mgmt);
            eventProducerService.produceOfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());
        }

        return responseEnvelope;
    }

    private void validateCredentialRequest(CredentialOffer credentialOffer, CredentialRequestClass credentialRequest) {
        var mgmt = credentialOffer.getCredentialManagement();

        // We have to check again that the Credential Status has not been changed to
        // catch race condition between holder & issuer
        if (!credentialOffer.getCredentialStatus()
                .equals(CredentialOfferStatusType.IN_PROGRESS)
                && !credentialOffer.getCredentialStatus()
                .equals(CredentialOfferStatusType.REQUESTED)) {
            log.info("Credential offer {} failed to create VC, as state was not IN_PROGRESS instead was {}",
                    credentialOffer.getId(), credentialOffer.getCredentialStatus());
            throw OAuthException.invalidGrant(String.format(
                    "Offer is not valid anymore. The current offer state is %s." +
                            "The user should probably contact the business issuer about this.",
                    credentialOffer.getCredentialStatus()));
        }

        // check if the offer is still valid
        if (mgmt.hasTokenExpirationPassed()) {
            log.info("Received AccessToken for credential offer {} was expired.", credentialOffer.getId());
            eventProducerService.produceErrorEvent("AccessToken expired, offer possibly stuck in IN_PROGRESS",
                    CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED,
                    credentialOffer);

            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst());

        if (!credentialConfiguration.getFormat()
                .equals(credentialRequest.getFormat())) {
            // This should only occur when the wallet has a bug
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_FORMAT, "Mismatch between requested and offered format.");
        }

        if (credentialRequest.getCredentialConfigurationId() != null
                && !credentialOffer.getMetadataCredentialSupportedId()
                .getFirst()
                .equals(credentialRequest.getCredentialConfigurationId())) {
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_TYPE,
                    "Mismatch between requested and offered credential configuration id.");
        }
    }

    private CredentialOffer getCredentialOfferByTransactionIdAndAccessToken(UUID transactionId, String accessToken) {
        CredentialManagement mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        var offers = mgmt.getCredentialOffers();

        return offers.stream().filter(o -> o.getTransactionId() != null
                        && o.getTransactionId().equals(transactionId))
                .findFirst()
                .orElseThrow(() -> new Oid4vcException(INVALID_TRANSACTION_ID, "Invalid transactional id"));
    }

    // todo check & maybe refactor
    private Optional<CredentialOffer> getFirstOffersInProgressAndCheckIfAnyOfferExpiredAndUpdate(CredentialManagement mgmt) {
        return mgmt.getCredentialOffers().stream()
                .map(offer -> {
                    if (offer.getCredentialStatus() != CredentialOfferStatusType.EXPIRED && offer.hasExpirationTimeStampPassed()) {
                        offer.markAsExpired();
                        return credentialOfferRepository.save(offer);
                    }
                    return offer;
                })
                .filter(offer -> offer.getCredentialStatus() == CredentialOfferStatusType.IN_PROGRESS)
                .findFirst();
    }
}