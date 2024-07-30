package ch.admin.bit.eid.issuer_management.services;

import ch.admin.bit.eid.issuer_management.config.ApplicationConfig;
import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.exceptions.BadRequestException;
import ch.admin.bit.eid.issuer_management.exceptions.ResourceNotFoundException;
import ch.admin.bit.eid.issuer_management.models.CredentialOffer;
import ch.admin.bit.eid.issuer_management.models.dto.CreateCredentialRequestDto;
import ch.admin.bit.eid.issuer_management.models.entities.CredentialOfferEntity;
import ch.admin.bit.eid.issuer_management.repositories.CredentialOfferRepository;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.nonNull;


@Service
@AllArgsConstructor
public class CredentialService {

    private final CredentialOfferRepository credentialOfferRepository;

    private final ApplicationConfig config;

    private final ObjectMapper objectMapper;

    public CredentialOfferEntity getCredential(UUID credentialId) {

        // Check if optional can be default
        return this.credentialOfferRepository.findById(credentialId)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    public CredentialOfferEntity createCredential(CreateCredentialRequestDto requestDto) {
        Instant expiration = Instant.now().plusSeconds(nonNull(requestDto.getOfferValiditySeconds())
                ? requestDto.getOfferValiditySeconds()
                : config.getOfferValidity());

        // todo move to mapper
        CredentialOfferEntity entity = CredentialOfferEntity.builder()
                .credentialStatus(CredentialStatusEnum.OFFERED)
                .metadataCredentialSupportedId(requestDto.getMetadataCredentialSupportedId())
                .offerData(requestDto.getCredentialSubjectData())
                .offerExpirationTimestamp(expiration.getEpochSecond())
                .holderBindingNonce(UUID.randomUUID())
                // TODO check if needs to be set on start
                .accessToken(UUID.randomUUID())
                // TODO check if output is the same as py isoformat()
                .credentialValidFrom(requestDto.getCredentialValidFrom())
                .credentialValidUntil(requestDto.getCredentialValidUntil())
                .build();

        return this.credentialOfferRepository.save(entity);
    }

    public CredentialOfferEntity updateCredentialStatus(@NotNull UUID credentialId,
                                                        @NotNull CredentialStatusEnum newStatus) {

        CredentialOfferEntity credential = this.getCredential(credentialId);

        // TODO rm status & credentialStatus
        boolean credentialStatus = Boolean.TRUE;
        CredentialStatusEnum currentStatus = credential.getCredentialStatus();

        if (currentStatus == newStatus || currentStatus == CredentialStatusEnum.REVOKED) {
            throw new BadRequestException(String.format("Tried to set %s but status is already %s", newStatus, currentStatus));
        }

        if (currentStatus.isPostHolderInteraction() && newStatus != CredentialStatusEnum.REVOKED) {
            if (currentStatus == CredentialStatusEnum.ISSUED) {
                credential.setCredentialStatus(newStatus);
            } else if (currentStatus.equals(newStatus)) {
                // TODO check -> Why
                // management.credential_status = db_credential.CredentialStatus.ISSUED.value;
            }

        } else if (currentStatus.isDuringHolderInteraction()) {
            // TODO Check
            credential.setCredentialStatus(CredentialStatusEnum.OFFERED);
        } else if (newStatus == CredentialStatusEnum.REVOKED) {
            credential.setCredentialStatus(newStatus);
            credential.setOfferData(null);
        } else {
            throw new BadRequestException(String.format("Status cannot be updated from %s to %s", currentStatus, newStatus));
        }

        return this.credentialOfferRepository.save(credential);
    }

    public String getOfferDeeplinkFromCredential(CredentialOfferEntity credential) {

        Map<String, Object> grants = new HashMap<>();
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", new Object() {
            // TODO check what this value is and where it should be stored
            @JsonProperty("pre-authorized_code")
            final UUID preAuthorizedCode = credential.getId();
        });

        CredentialOffer credentialOffer = CredentialOffer.builder()
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
}
