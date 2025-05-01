/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialOfferDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.StatusResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.*;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSSigner;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.HashMap;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer.readOfferData;
import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.*;
import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;
import static ch.admin.bj.swiyu.issuer.service.CredentialOfferMapper.*;
import static ch.admin.bj.swiyu.issuer.service.mapper.CredentialRequestMapper.toCredentialRequest;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.StatusResponseMapper.toStatusResponseDto;
import static java.util.Objects.isNull;

@Slf4j
@Service
@AllArgsConstructor
public class CredentialService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final ApplicationProperties config;
    private final ObjectMapper objectMapper;
    private final StatusListService statusListService;
    private final IssuerMetadataTechnical issuerMetadata;
    private final CredentialFormatFactory vcFormatFactory;
    private final ApplicationProperties applicationProperties; // TODO gapa: remove this and use config
    private final JWSSigner signer;
    private final OpenIdIssuerConfiguration openIDConfiguration;

    @Transactional // not readonly since expired credentails gets updated here automatically
    public Object getCredentialOffer(UUID credentialId) {
        return toCredentialWithDeeplinkResponseDto(this.getCredential(credentialId));
    }

    @Transactional // not readonly since expired credentails gets updated here automatically
    public String getCredentialOfferDeeplink(UUID credentialId) {
        var credential = this.getCredential(credentialId);
        return this.getOfferDeeplinkFromCredential(credential);

    }

    @Transactional
    public UpdateStatusResponseDto updateCredentialStatus(@NotNull UUID credentialId,
                                                          @NotNull UpdateCredentialStatusRequestTypeDto requestedNewStatus) {
        var credential = updateCredentialStatus(getCredentialForUpdate(credentialId), toCredentialStatusType(requestedNewStatus));
        return toUpdateStatusResponseDto(credential);
    }

    @Transactional // not readonly since expired credentails gets updated here automatically
    public StatusResponseDto getCredentialStatus(UUID credentialId) {
        CredentialOffer credential = this.getCredential(credentialId);
        return toStatusResponseDto(credential);
    }

    @Transactional
    public CredentialWithDeeplinkResponseDto createCredential(@Valid CreateCredentialRequestDto request) {
        var credential = this.createCredentialOffer(request);
        var offerLinkString = this.getOfferDeeplinkFromCredential(credential);
        return CredentialOfferMapper.toCredentialWithDeeplinkResponseDto(credential, offerLinkString);
    }

    /**
     * Set the state of all expired credential offers to expired and delete the person data associated with it.
     */
    @Scheduled(initialDelay = 0, fixedDelayString = "${application.offer-expiration-interval}")
    @SchedulerLock(name = "expireOffers")
    @Transactional
    public void expireOffers() {
        var expireStates = CredentialStatusType.getExpirableStates();
        var expireTimeStamp = Instant.now().getEpochSecond();
        log.info("Expiring {} offers", credentialOfferRepository.countByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp));
        var expiredOffers = credentialOfferRepository.findByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp);
        expiredOffers.forEach(offer -> updateCredentialStatus(offer, CredentialStatusType.EXPIRED));
    }

    /**
     * Returns the credential offer for the given id.
     * <p>
     * Attention: If it is expired it will updated its state before returning it.
     */
    private CredentialOffer getCredential(UUID credentialId) {

        // Check if optional can be default
        return this.credentialOfferRepository.findById(credentialId)
                .map(offer -> {
                    // Make sure only offer is returned if it is not expired
                    if (CredentialStatusType.getExpirableStates().contains(offer.getCredentialStatus()) && offer.hasExpirationTimeStampPassed()) {
                        return updateCredentialStatus(getCredentialForUpdate(offer.getId()), CredentialStatusType.EXPIRED);
                    }
                    return offer;
                })
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    /**
     * @param credential the pessimistic write locked credential offer
     * @param newStatus  the new status assigned
     * @return the updated CredentialOffer
     */
    private CredentialOffer updateCredentialStatus(@NotNull CredentialOffer credential,
                                                   @NotNull CredentialStatusType newStatus) {

        var currentStatus = credential.getCredentialStatus();

        // Ignore no status changes and return. This needs to be checked first to prevent unnecessary errors
        if (currentStatus == newStatus) {
            return credential;
        }

        // status is already in a terminal state and cannot be changed
        if (currentStatus.isTerminalState()) {
            throw new BadRequestException(String.format("Tried to set %s but status is already %s", newStatus, currentStatus));
        }

        if (newStatus == CredentialStatusType.EXPIRED) {
            credential.expire();
        } else if (!currentStatus.isIssuedToHolder()) {
            handlePreIssuanceStatusChange(credential, currentStatus, newStatus);
        } else {
            handlePostIssuanceStatusChange(credential, newStatus);
        }

        log.info(String.format("Updating %s from %s to %s", credential.getId(), currentStatus, newStatus));
        return this.credentialOfferRepository.save(credential);
    }

    /**
     * Handles status changes before issuance (status cancelled, ready and expired)
     */
    private void handlePreIssuanceStatusChange(CredentialOffer credential,
                                               CredentialStatusType currentStatus,
                                               CredentialStatusType newStatus) {

        // if the new status is READY, then we can only set it if the old status was deferred
        if (currentStatus == CredentialStatusType.DEFERRED && newStatus == CredentialStatusType.READY) {
            credential.changeStatus(CredentialStatusType.READY);
            return;
        }

        if (newStatus == CredentialStatusType.CANCELLED || newStatus == CredentialStatusType.REVOKED) {
            credential.cancel();
            return;
        }

        throw new BadRequestException(String.format(
                "Illegal state transition - Status cannot be updated from %s to %s", currentStatus, newStatus));
    }

    /**
     * Handles status changes after issuance (status suspended, revoked and issued)
     */
    private void handlePostIssuanceStatusChange(CredentialOffer credential, CredentialStatusType newStatus) {

        final Set<CredentialOfferStatus> offerStatusSet = credential.getOfferStatusSet();

        if (offerStatusSet.isEmpty()) {
            throw new BadRequestException("No associated status lists found. Can not set a status to an already issued credential");
        }

        switch (newStatus) {
            case REVOKED -> statusListService.revoke(offerStatusSet);
            case SUSPENDED -> statusListService.suspend(offerStatusSet);
            case ISSUED -> statusListService.revalidate(offerStatusSet);
            default -> throw new BadRequestException(String.format(
                    "Illegal state transition - Status cannot be updated from %s to %s", credential.getCredentialStatus(), newStatus));
        }

        credential.changeStatus(newStatus);
    }

    private CredentialOffer getCredentialForUpdate(UUID credentialId) {
        return this.credentialOfferRepository.findByIdForUpdate(credentialId)
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    private CredentialOffer createCredentialOffer(CreateCredentialRequestDto requestDto) {
        var expiration = Instant.now().plusSeconds(requestDto.getOfferValiditySeconds() > 0
                ? requestDto.getOfferValiditySeconds()
                : config.getOfferValidity());

        var statusListUris = requestDto.getStatusLists();
        var statusLists = statusListService.findByUriIn(statusListUris);
        if (statusLists.size() != requestDto.getStatusLists().size()) {
            throw new BadRequestException(String.format("Could not resolve all provided status lists, only found %s",
                    statusLists.stream().map(StatusList::getUri).collect(Collectors.joining(", "))));
        }

        var entity = CredentialOffer.builder()
                .credentialStatus(CredentialStatusType.OFFERED)
                .metadataCredentialSupportedId(requestDto.getMetadataCredentialSupportedId())
                .offerData(readOfferData(requestDto.getCredentialSubjectData()))
                .offerExpirationTimestamp(expiration.getEpochSecond())
                .nonce(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialValidFrom(requestDto.getCredentialValidFrom())
                .credentialValidUntil(requestDto.getCredentialValidUntil())
                .credentialMetadata(Optional.ofNullable(requestDto.getCredentialMetadata()).orElse(new HashMap<>()))
                .build();
        entity = this.credentialOfferRepository.save(entity);

        // Add Status List links
        for (StatusList statusList : statusLists) {
            var offerStatusKey = CredentialOfferStatusKey.builder()
                    .offerId(entity.getId())
                    .statusListId(statusList.getId())
                    .build();
            var offerStatus = CredentialOfferStatus.builder()
                    .id(offerStatusKey)
                    .index(statusList.getNextFreeIndex())
                    .offer(entity)
                    .build();
            credentialOfferStatusRepository.save(offerStatus);
            statusListService.incrementNextFreeIndex(statusList.getId());
        }
        return entity;
    }

    private String getOfferDeeplinkFromCredential(CredentialOffer credential) {
        var grants = new HashMap<String, Object>();
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", new Object() {
            @JsonProperty("pre-authorized_code")
            final UUID preAuthorizedCode = credential.getPreAuthorizedCode();
        });

        var credentialOffer = CredentialOfferDto.builder()
                .credentialIssuer(config.getExternalUrl())
                .credentials(credential.getMetadataCredentialSupportedId())
                .grants(grants)
                .version(config.getRequestOfferVersion())
                .build();

        String credentialOfferString = null;
        try {
            credentialOfferString = URLEncoder.encode(objectMapper.writeValueAsString(credentialOffer),
                    Charset.defaultCharset());
        } catch (JsonProcessingException e) {
            throw new JsonException("Error processing credential offer for credential with id %s".formatted(credential.getId()), e);
        }

        return String.format("%s://?credential_offer=%s", config.getDeeplinkSchema(), credentialOfferString);
    }

    @Transactional
    public CredentialEnvelopeDto createCredential(CredentialRequestDto credentialRequestDto, String accessToken) {

        var credentialRequest = toCredentialRequest(credentialRequestDto);

        CredentialOffer credentialOffer = getCredentialOfferByAccessToken(accessToken);

        // We have to check again that the Credential Status has not been changed to
        // catch race condition between holder & issuer
        if (!credentialOffer.getCredentialStatus().equals(CredentialStatusType.IN_PROGRESS)) {
            throw OAuthException.invalidGrant(String.format(
                    "Offer is not valid anymore. The current offer state is %s." +
                            "The user should probably contact the business issuer about this.",
                    credentialOffer.getCredentialStatus()));
        }

        if (credentialOffer.hasTokenExpirationPassed()) {
            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        if (!credentialConfiguration.getFormat().equals(credentialRequest.getFormat())) {
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_FORMAT, "Mismatch between requested and offered format.");
        }

        var holderPublicKey = getHolderPublicKey(credentialRequest, credentialOffer);

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
            credentialOffer.markAsDeferred(deferredData.transactionId(), credentialRequest, holderPublicKey.orElse(null));
        } else {
            responseEnvelope = vcBuilder.buildCredential();
            credentialOffer.markAsIssued();
        }

        credentialOfferRepository.save(credentialOffer);
        return responseEnvelope;
    }

    @Transactional
    public CredentialEnvelopeDto createCredentialFromDeferredRequest(DeferredCredentialRequestDto deferredCredentialRequest,
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
            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        var credentialRequest = credentialOffer.getCredentialRequest();

        if (isNull(credentialRequest)) {
            throw new IllegalArgumentException("Credential Request is missing");
        }

        // Get holder public key which was stored in the credential request
        Optional<String> holderPublicKey = Optional.of(credentialOffer.getHolderJWK());

        CredentialEnvelopeDto vc = vcFormatFactory
                // get first entry because we expect the list to only contain one item
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .holderBinding(holderPublicKey)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredential();

        credentialOffer.markAsIssued();

        credentialOfferRepository.save(credentialOffer);
        return vc;
    }

    /**
     * Issues an OAuth token for a given pre-authorization code created by issuer mgmt
     *
     * @param preAuthCode Pre authorization code of holder
     * @return OAuth authorization token which can be used in credential service endpoint
     */
    @Transactional
    public OAuthTokenDto issueOAuthToken(String preAuthCode) {
        var offer = getCredentialOfferByPreAuthCode(preAuthCode);

        if (offer.getCredentialStatus() != CredentialStatusType.OFFERED) {
            throw OAuthException.invalidGrant("Credential has already been used");
        }
        log.info("Pre-Authorized code consumed, sending Access Token {}. Management ID is {} and new status is {}",
                offer.getAccessToken(), offer.getId(), offer.getCredentialStatus());
        offer.markAsInProgress();
        offer.setTokenIssuanceTimestamp(applicationProperties.getTokenTTL());

        credentialOfferRepository.saveAndFlush(offer);

        return OAuthTokenDto.builder()
                .accessToken(offer.getAccessToken().toString())
                .expiresIn(applicationProperties.getTokenTTL())
                .cNonce(offer.getNonce().toString())
                .build();
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
            throw new Oid4vcException(INVALID_CREDENTIAL_REQUEST, "Invalid transactional id");
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
     * @param credentialRequest the credential request to be processed
     * @param credentialOffer   the credential offer for which the request was sent
     * @return the holder's public key or an empty optional
     * if for the offered credential no holder binding is required
     * @throws Oid4vcException if the credential request is invalid in some form
     */
    private Optional<String> getHolderPublicKey(CredentialRequestClass credentialRequest, CredentialOffer credentialOffer) {
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        // Process Holder Binding if a Proof Type is required
        var proofTypes = credentialConfiguration.getProofTypesSupported();
        if (proofTypes != null && !proofTypes.isEmpty()) {
            var requestProof = credentialRequest.getProof(applicationProperties.getAcceptableProofTimeWindowSeconds())
                    .orElseThrow(
                            () -> new Oid4vcException(INVALID_PROOF,
                                    "Proof must be provided for the requested credential"));
            var bindingProofType = Optional.of(proofTypes.get(requestProof.proofType.toString()))
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
            } catch (IOException e) {
                throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
            }
            return Optional.of(requestProof.getBinding());
        }
        return Optional.empty();
    }

}