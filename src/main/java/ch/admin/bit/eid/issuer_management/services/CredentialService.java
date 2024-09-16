package ch.admin.bit.eid.issuer_management.services;

import ch.admin.bit.eid.issuer_management.config.ApplicationProperties;
import ch.admin.bit.eid.issuer_management.domain.CredentialOfferRepository;
import ch.admin.bit.eid.issuer_management.domain.CredentialOfferStatusRepository;
import ch.admin.bit.eid.issuer_management.domain.StatusListRepository;
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
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.util.Objects.nonNull;


@Slf4j
@Service
@AllArgsConstructor
public class CredentialService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final StatusListRepository statusListRepository;

    private final ApplicationProperties config;

    private final ObjectMapper objectMapper;

    private final StatusListService statusListService;

    public CredentialOffer getCredential(UUID credentialId) {

        // Check if optional can be default
        return this.credentialOfferRepository.findById(credentialId)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    public CredentialOffer createCredential(CreateCredentialRequestDto requestDto) {
        Instant expiration = Instant.now().plusSeconds(nonNull(requestDto.getOfferValiditySeconds())
                ? requestDto.getOfferValiditySeconds()
                : config.getOfferValidity());


        List<StatusList> statusLists = statusListRepository.findByUriIn(requestDto.getStatusLists());
        if (statusLists.size() != requestDto.getStatusLists().size()) {
            throw new BadRequestException(String.format("Could not resolve all provided status lists, only found %s", statusLists.stream().map(StatusList::getUri).collect(Collectors.joining(", "))));
        }

        CredentialOffer entity = CredentialOffer.builder()
                .credentialStatus(CredentialStatusEnum.OFFERED)
                .metadataCredentialSupportedId(requestDto.getMetadataCredentialSupportedId())
                .offerData(requestDto.getCredentialSubjectData())
                .offerExpirationTimestamp(expiration.getEpochSecond())
                .holderBindingNonce(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialValidFrom(requestDto.getCredentialValidFrom())
                .credentialValidUntil(requestDto.getCredentialValidUntil())
                .build();
        entity = this.credentialOfferRepository.save(entity);

        // Add Status List links
        for (StatusList statusList : statusLists) {
            CredentialOfferStatusKey offerStatusKey = CredentialOfferStatusKey.builder().offerId(entity.getId()).statusListId(statusList.getId()).build();
            CredentialOfferStatus offerStatus = CredentialOfferStatus.builder().id(offerStatusKey).index(statusList.getLastUsedIndex()).offer(entity).statusList(statusList).build();
            statusList.setLastUsedIndex(statusList.getLastUsedIndex() + 1);
            credentialOfferStatusRepository.save(offerStatus);
            statusListRepository.save(statusList);

        }
        return entity;
    }

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
            if (newStatus == CredentialStatusEnum.REVOKED) {
                credential.setOfferData(null);
            } else if (newStatus == CredentialStatusEnum.OFFERED && currentStatus == CredentialStatusEnum.IN_PROGRESS) {
                credential.setCredentialStatus(newStatus);
            } else {
                throw new BadRequestException(String.format("Illegal state transition - Status cannot be updated from %s to %s", currentStatus, newStatus));
            }
        } else {
            switch (newStatus) {
                case REVOKED -> statusListService.revoke(credential.getOfferStatusSet());
                case SUSPENDED -> statusListService.suspend(credential.getOfferStatusSet());
                case ISSUED -> statusListService.unsuspend(credential.getOfferStatusSet());
                default -> {
                }
            }

        }

        log.info(String.format("Updating %s from %s to %s", credentialId, currentStatus, newStatus));
        credential.setCredentialStatus(newStatus);
        return this.credentialOfferRepository.save(credential);
    }

    public String getOfferDeeplinkFromCredential(CredentialOffer credential) {

        Map<String, Object> grants = new HashMap<>();
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", new Object() {
            // TODO check what this value is and where it should be stored
            @JsonProperty("pre-authorized_code")
            final UUID preAuthorizedCode = credential.getId();
        });

        ch.admin.bit.eid.issuer_management.models.CredentialOffer credentialOffer = ch.admin.bit.eid.issuer_management.models.CredentialOffer.builder()
                .credentialIssuer(config.getExternalUrl())
                .credentials(credential.getMetadataCredentialSupportedId())
                .grants(grants)
                .build();

        String credentialOfferString = null;

        try {
            credentialOfferString = URLEncoder.encode(objectMapper.writeValueAsString(credentialOffer), Charset.defaultCharset().toString());
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        return String.format("openid-credential-offer://?credential_offer=%s", credentialOfferString);
    }


    private void setCredentialStatus(CredentialOffer offer, CredentialStatusEnum status) {
        if (offer.getOfferStatusSet().isEmpty()) {
            throw new BadRequestException(String.format("%s has no status list which could reflect the change to status %s", offer.getId(), status));
        }

    }
}
