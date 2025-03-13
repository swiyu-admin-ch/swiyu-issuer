/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service;

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.HashMap;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOffer.readOfferData;
import static ch.admin.bj.swiyu.issuer.management.service.CredentialOfferMapper.*;
import static ch.admin.bj.swiyu.issuer.management.service.statusregistry.StatusResponseMapper.toStatusResponseDto;

import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CredentialOfferDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.StatusResponseDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.management.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.management.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.management.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.management.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.*;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@AllArgsConstructor
public class CredentialService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final ApplicationProperties config;
    private final ObjectMapper objectMapper;
    private final StatusListService statusListService;

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
                                                          @NotNull CredentialStatusTypeDto requestedNewStatus) {
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

        // Ignore no status changes and return
        if (currentStatus == newStatus) {
            return credential;
        }

        // should not be able to change status to other than revoked if it is already revoked
        if (currentStatus == CredentialStatusType.REVOKED) {
            throw new BadRequestException(
                    String.format("Tried to set %s but status is already %s", newStatus, currentStatus));
        }

        if (newStatus == CredentialStatusType.EXPIRED) {
            credential.changeStatus(CredentialStatusType.EXPIRED);
            credential.removeOfferData();
        } else if (!currentStatus.isIssuedToHolder()) {
            // Status before issuance is not reflected in the status list
            if (newStatus == CredentialStatusType.REVOKED || newStatus == CredentialStatusType.CANCELLED) {
                credential.removeOfferData();
                newStatus = CredentialStatusType.CANCELLED; // Use the correct status for status tracking
            } else if (!(newStatus == CredentialStatusType.OFFERED
                    && currentStatus == CredentialStatusType.IN_PROGRESS)) {
                // Only allowed transition is to reset from IN_PROGRESS to OFFERED so the offer
                // can be used again.
                throw new BadRequestException(String.format(
                        "Illegal state transition - Status cannot be updated from %s to %s", currentStatus, newStatus));
            }
        } else {

            final Set<CredentialOfferStatus> offerStatusSet = credential.getOfferStatusSet();
            if (offerStatusSet.isEmpty()) {
                throw new BadRequestException("No associated status lists found. Can not set a status to an already issued credential");
            }
            switch (newStatus) {
                case REVOKED -> statusListService.revoke(offerStatusSet);
                case SUSPENDED -> statusListService.suspend(offerStatusSet);
                case ISSUED -> statusListService.revalidate(offerStatusSet);
                default -> throw new IllegalArgumentException("Unknown status");
            }

        }

        log.info(String.format("Updating %s from %s to %s", credential.getId(), currentStatus, newStatus));
        credential.changeStatus(newStatus);
        return this.credentialOfferRepository.save(credential);
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

    // protected because it is used for testing
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
}
