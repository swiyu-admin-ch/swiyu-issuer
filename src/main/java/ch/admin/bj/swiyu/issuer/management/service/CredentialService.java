package ch.admin.bj.swiyu.issuer.management.service;

import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CredentialOfferDto;
import ch.admin.bj.swiyu.issuer.management.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferEntity;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.management.domain.credentialofferstatus.CredentialOfferStatusEntity;
import ch.admin.bj.swiyu.issuer.management.domain.credentialofferstatus.CredentialOfferStatusKey;
import ch.admin.bj.swiyu.issuer.management.domain.credentialofferstatus.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.management.domain.status_list.StatusListEntity;
import ch.admin.bj.swiyu.issuer.management.enums.CredentialStatusEnum;
import ch.admin.bj.swiyu.issuer.management.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.management.exception.JsonException;
import ch.admin.bj.swiyu.issuer.management.exception.ResourceNotFoundException;
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
import java.util.UUID;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferEntity.readOfferData;
import static java.util.Objects.nonNull;

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
    public CredentialOfferEntity getCredential(UUID credentialId) {

        // Check if optional can be default
        return this.credentialOfferRepository.findById(credentialId)
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    @Transactional
    public CredentialOfferEntity createCredential(CreateCredentialRequestDto requestDto) {
        var expiration = Instant.now().plusSeconds(nonNull(requestDto.getOfferValiditySeconds())
                ? requestDto.getOfferValiditySeconds()
                : config.getOfferValidity());

        var statusListUris = requestDto.getStatusLists();
        var statusLists = statusListService.findByUriIn(statusListUris);
        if (statusLists.size() != requestDto.getStatusLists().size()) {
            throw new BadRequestException(String.format("Could not resolve all provided status lists, only found %s",
                    statusLists.stream().map(StatusListEntity::getUri).collect(Collectors.joining(", "))));
        }

        var entity = CredentialOfferEntity.builder()
                .credentialStatus(CredentialStatusEnum.OFFERED)
                .metadataCredentialSupportedId(requestDto.getMetadataCredentialSupportedId())
                .offerData(readOfferData(requestDto.getCredentialSubjectData()))
                .offerExpirationTimestamp(expiration.getEpochSecond())
                .holderBindingNonce(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialValidFrom(requestDto.getCredentialValidFrom())
                .credentialValidUntil(requestDto.getCredentialValidUntil())
                .build();
        entity = this.credentialOfferRepository.save(entity);

        // Add Status List links
        for (StatusListEntity statusList : statusLists) {
            var offerStatusKey = CredentialOfferStatusKey.builder()
                    .offerId(entity.getId())
                    .statusListId(statusList.getId())
                    .build();
            var offerStatus = CredentialOfferStatusEntity.builder()
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
    public CredentialOfferEntity updateCredentialStatus(@NotNull UUID credentialId,
                                                        @NotNull CredentialStatusEnum newStatus) {
        CredentialOfferEntity credential = this.getCredential(credentialId);
        CredentialStatusEnum currentStatus = credential.getCredentialStatus();

        // No status change or was already revoked
        if (currentStatus == newStatus || currentStatus == CredentialStatusEnum.REVOKED) {
            throw new BadRequestException(
                    String.format("Tried to set %s but status is already %s", newStatus, currentStatus));
        }

        if (!currentStatus.isIssuedToHolder()) {
            // Status before issuance is not reflected in the status list
            if (newStatus == CredentialStatusEnum.REVOKED || newStatus == CredentialStatusEnum.CANCELLED) {
                credential.removeOfferData();
                newStatus = CredentialStatusEnum.CANCELLED; // Use the correct status for status tracking
            } else if (!(newStatus == CredentialStatusEnum.OFFERED
                    && currentStatus == CredentialStatusEnum.IN_PROGRESS)) {
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

        log.info(String.format("Updating %s from %s to %s", credentialId, currentStatus, newStatus));
        credential.changeStatus(newStatus);
        return this.credentialOfferRepository.save(credential);
    }

    @Transactional
    public String getOfferDeeplinkFromCredential(CredentialOfferEntity credential) {
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
        var expiredOffers = credentialOfferRepository.findByCredentialStatusAndOfferExpirationTimestampLessThan(CredentialStatusEnum.OFFERED, Instant.now().getEpochSecond());
        expiredOffers.forEach(offer -> {
            offer.changeStatus(CredentialStatusEnum.EXPIRED);
            offer.removeOfferData();
        });
    }
}
