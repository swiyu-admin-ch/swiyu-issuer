package ch.admin.bit.eid.issuer_management.services;

import ch.admin.bit.eid.issuer_management.config.ApplicationProperties;
import ch.admin.bit.eid.issuer_management.domain.CredentialOfferRepository;
import ch.admin.bit.eid.issuer_management.domain.CredentialOfferStatusRepository;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOfferStatus;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOfferStatusKey;
import ch.admin.bit.eid.issuer_management.domain.entities.StatusList;
import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.exceptions.BadRequestException;
import ch.admin.bit.eid.issuer_management.exceptions.ResourceNotFoundException;
import ch.admin.bit.eid.issuer_management.models.dto.CreateCredentialRequestDto;
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

import static ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer.readOfferData;
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
    public CredentialOffer getCredential(UUID credentialId) {

        // Check if optional can be default
        return this.credentialOfferRepository.findById(credentialId)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    @Transactional
    public CredentialOffer createCredential(CreateCredentialRequestDto requestDto) {
        var expiration = Instant.now().plusSeconds(nonNull(requestDto.getOfferValiditySeconds())
                ? requestDto.getOfferValiditySeconds()
                : config.getOfferValidity());

        var statusListUris = requestDto.getStatusLists();
        var statusLists = statusListService.findByUriIn(statusListUris);
        if (statusLists.size() != requestDto.getStatusLists().size()) {
            throw new BadRequestException(String.format("Could not resolve all provided status lists, only found %s", statusLists.stream().map(StatusList::getUri).collect(Collectors.joining(", "))));
        }

        var entity = CredentialOffer.builder()
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
                                                  @NotNull CredentialStatusEnum newStatus) {
        CredentialOffer credential = this.getCredential(credentialId);
        CredentialStatusEnum currentStatus = credential.getCredentialStatus();

        // No status change or was already revoked
        if (currentStatus == newStatus || currentStatus == CredentialStatusEnum.REVOKED) {
            throw new BadRequestException(String.format("Tried to set %s but status is already %s", newStatus, currentStatus));
        }

        if (!currentStatus.isIssuedToHolder()) {
            // Status before issuance is not reflected in the status list
            if (newStatus == CredentialStatusEnum.REVOKED || newStatus == CredentialStatusEnum.CANCELLED) {
                credential.removeOfferData();
                newStatus = CredentialStatusEnum.CANCELLED; // Use the correct status for status tracking
            } else if (!(newStatus == CredentialStatusEnum.OFFERED && currentStatus == CredentialStatusEnum.IN_PROGRESS)) {
                // Only allowed transition is to reset from IN_PROGRESS to OFFERED so the offer can be used again.
                throw new BadRequestException(String.format("Illegal state transition - Status cannot be updated from %s to %s", currentStatus, newStatus));
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
    public String getOfferDeeplinkFromCredential(CredentialOffer credential) {
        var grants = new HashMap<String, Object>();
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", new Object() {
            // TODO check what this value is and where it should be stored
            @JsonProperty("pre-authorized_code")
            final UUID preAuthorizedCode = credential.getId();
        });

        var credentialOffer = ch.admin.bit.eid.issuer_management.models.CredentialOffer.builder()
                .credentialIssuer(config.getExternalUrl())
                .credentials(credential.getMetadataCredentialSupportedId())
                .grants(grants)
                .build();

        String credentialOfferString = null;
        try {
            credentialOfferString = URLEncoder.encode(objectMapper.writeValueAsString(credentialOffer), Charset.defaultCharset());
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
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
