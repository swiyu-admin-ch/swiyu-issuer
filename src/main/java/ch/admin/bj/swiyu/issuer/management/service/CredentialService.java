/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service;

import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CredentialOfferDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.management.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.management.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.management.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.management.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferStatusKey;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusList;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOffer.readOfferData;
import static ch.admin.bj.swiyu.issuer.management.service.CredentialOfferMapper.toCredentialStatusType;

@Slf4j
@Service
@AllArgsConstructor
public class CredentialService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final ApplicationProperties config;
    private final ObjectMapper objectMapper;
    private final StatusListService statusListService;

    @Transactional
    public CredentialOffer getCredential(UUID credentialId) {

        // Check if optional can be default
        return this.credentialOfferRepository.findById(credentialId)
                .map(offer -> {
                    // Make sure only offer is returned if it is not expired
                    if (offer.getCredentialStatus() != CredentialStatusType.EXPIRED && offer.hasExpirationTimeStampPassed()) {
                        return updateCredentialStatus(getCredentialForUpdate(offer.getId()), CredentialStatusType.EXPIRED);
                    }
                    return offer;
                })
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    public CredentialOffer getCredentialForUpdate(UUID credentialId) {
        return this.credentialOfferRepository.findByIdForUpdate(credentialId)
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    @Transactional
    public CredentialOffer createCredential(CreateCredentialRequestDto requestDto) {
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
                .credentialValidFrom(requestDto.getCredentialValidFrom())
                .credentialValidUntil(requestDto.getCredentialValidUntil())
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
                    .statusList(statusList)
                    .build();
            credentialOfferStatusRepository.save(offerStatus);
            statusListService.incrementNextFreeIndex(statusList.getId());
        }
        return entity;
    }


    @Transactional
    public CredentialOffer updateCredentialStatus(@NotNull UUID credentialId,
                                                  @NotNull CredentialStatusTypeDto requestedNewStatus) {
        return updateCredentialStatus(getCredentialForUpdate(credentialId), toCredentialStatusType(requestedNewStatus));
    }

    /**
     * @param credential the pessimistic write locked credential offer
     * @param newStatus  the new status assigned
     * @return the updated CredentialOffer
     */
    @Transactional
    protected CredentialOffer updateCredentialStatus(@NotNull CredentialOffer credential,
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
            switch (newStatus) {
                case REVOKED -> statusListService.revoke(credential.getOfferStatusSet());
                case SUSPENDED -> statusListService.suspend(credential.getOfferStatusSet());
                case ISSUED -> statusListService.revalidate(credential.getOfferStatusSet());
                default -> throw new IllegalArgumentException("Unknown status");
            }

        }

        log.info(String.format("Updating %s from %s to %s", credential.getId(), currentStatus, newStatus));
        credential.changeStatus(newStatus);
        return this.credentialOfferRepository.save(credential);
    }

    @Transactional
    public String getOfferDeeplinkFromCredential(CredentialOffer credential) {
        var grants = new HashMap<String, Object>();
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", new Object() {
            // TODO check what this value is and where it should be stored
            @JsonProperty("pre-authorized_code")
            final UUID preAuthorizedCode = credential.getId();
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

        return String.format("openid-credential-offer://?credential_offer=%s", credentialOfferString);
    }

    /**
     * Set the state of all expired credential offers to expired and delete the person data associated with it.
     */
    @Scheduled(initialDelay = 0, fixedDelayString = "${application.offer-expiration-interval}")
    @SchedulerLock(name = "expireOffers")
    @Transactional
    public void expireOffers() {
        var expireStates = List.of(CredentialStatusType.OFFERED, CredentialStatusType.IN_PROGRESS);
        var expireTimeStamp = Instant.now().getEpochSecond();
        log.info("Expiring {} offers", credentialOfferRepository.countByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp));
        var expiredOffers = credentialOfferRepository.findByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp);
        expiredOffers.forEach(offer -> updateCredentialStatus(offer, CredentialStatusType.EXPIRED));
    }
}
