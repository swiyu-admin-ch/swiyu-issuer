package ch.admin.bj.swiyu.issuer.service.offer;

import ch.admin.bj.swiyu.issuer.dto.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.renewal.RenewalResponseDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.experimental.UtilityClass;
import org.jspecify.annotations.Nullable;
import org.springframework.util.CollectionUtils;

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.service.credential.CredentialRequestMapper.toCredentialRequest;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.StatusResponseMapper.toCredentialStatusTypeDto;
import static java.util.Objects.isNull;

@UtilityClass
public class CredentialOfferMapper {

    public static CredentialWithDeeplinkResponseDto toCredentialWithDeeplinkResponseDto(ApplicationProperties props,
                                                                                        CredentialManagement management,
                                                                                        CredentialOffer credentialOffer) {
        return CredentialWithDeeplinkResponseDto.builder()
                .managementId(management.getId())
                .offerId(credentialOffer.getId())
                .offerDeeplink(getOfferDeeplinkFromCredential(props, credentialOffer))
                .build();
    }

    public static List<CredentialInfoResponseDto> toCredentialInfoResponseDtoList(ApplicationProperties props, Set<CredentialOffer> credentialOffers) {
        return credentialOffers.stream()
                .map(credential -> toCredentialInfoResponseDto(credential, props))
                .toList();
    }

    public static CredentialInfoResponseDto toCredentialInfoResponseDto(CredentialOffer credential, ApplicationProperties props) {
        return new CredentialInfoResponseDto(
                toCredentialStatusTypeDto(credential.getCredentialStatus()),
                credential.getMetadataCredentialSupportedId(),
                toCredentialOfferMetadata(credential.getCredentialMetadata()),
                nullIfEmptyList(credential.getHolderJWKs()),
                nullIfEmptyList(credential.getKeyAttestations()),
                toClientAgentInfoDto(credential.getClientAgentInfo()),
                credential.getOfferExpirationTimestamp(),
                credential.getDeferredOfferValiditySeconds(),
                credential.getCredentialValidFrom(),
                credential.getCredentialValidUntil(),
                toCredentialRequest(credential.getCredentialRequest()),
                getOfferDeeplinkFromCredential(props, credential),
                nullIfEmptyList(credential.getVcHashes())
        );
    }

    private static @Nullable List<String> nullIfEmptyList(List<String> credential) {
        return !CollectionUtils.isEmpty(credential) ? credential : null;
    }

    public static ClientAgentInfoDto toClientAgentInfoDto(ClientAgentInfo clientAgentInfo) {
        if (clientAgentInfo == null) {
            return null;
        }
        return new ClientAgentInfoDto(
                clientAgentInfo.remoteAddr(),
                clientAgentInfo.userAgent(),
                clientAgentInfo.acceptLanguage(),
                clientAgentInfo.acceptEncoding()
        );
    }

    public static Object toCredentialWithDeeplinkResponseDto(CredentialOffer credential) {
        Map<String, Object> offerData = credential.getOfferData();
        if (offerData != null && offerData.containsKey("data")) {
            return offerData.get("data");
        }
        return offerData;
    }

    public static UpdateStatusResponseDto toUpdateStatusResponseDto(CredentialOffer credential) {
        return UpdateStatusResponseDto.builder()
                .id(credential.getId())
                .credentialStatus(toCredentialStatusTypeDto(credential.getCredentialStatus()))
                .build();
    }

    public static UpdateStatusResponseDto toUpdateStatusResponseDto(CredentialOffer credential, List<UUID> statusLists) {
        return UpdateStatusResponseDto.builder()
                .id(credential.getId())
                .credentialStatus(toCredentialStatusTypeDto(credential.getCredentialStatus()))
                .statusLists(statusLists)
                .build();
    }

    public static CredentialOfferStatusType toCredentialStatusType(CredentialStatusTypeDto source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case OFFERED -> CredentialOfferStatusType.OFFERED;
            case CANCELLED -> CredentialOfferStatusType.CANCELLED;
            case IN_PROGRESS -> CredentialOfferStatusType.IN_PROGRESS;
            case DEFERRED -> CredentialOfferStatusType.DEFERRED;
            case READY -> CredentialOfferStatusType.READY;
            case ISSUED -> CredentialOfferStatusType.ISSUED;
            case INIT -> null;
            case SUSPENDED -> null;
            case REVOKED -> null;
            case REQUESTED -> CredentialOfferStatusType.REQUESTED;
            case EXPIRED -> CredentialOfferStatusType.EXPIRED;
        };
    }

    public static CredentialOfferStatusType toCredentialStatusType(UpdateCredentialStatusRequestTypeDto source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case CANCELLED -> CredentialOfferStatusType.CANCELLED;
            case READY -> CredentialOfferStatusType.READY;
            case ISSUED -> CredentialOfferStatusType.ISSUED;
            case SUSPENDED -> null;
            case REVOKED -> null;
        };
    }

    /**
     * Merges {@code override} into {@code base}. Non-null fields in {@code override} win.
     * Does not mutate inputs.
     */
    public static ConfigurationOverride mergeConfigurationOverride(ConfigurationOverride base, ConfigurationOverride override) {
        if (override == null) {
            return base;
        }
        if (base == null) {
            return override;
        }
        return new ConfigurationOverride(
                override.issuerDid() != null ? override.issuerDid() : base.issuerDid(),
                override.verificationMethod() != null ? override.verificationMethod() : base.verificationMethod(),
                override.keyId() != null ? override.keyId() : base.keyId(),
                override.keyPin() != null ? override.keyPin() : base.keyPin()
        );
    }

    public static ConfigurationOverride toConfigurationOverride(ConfigurationOverrideDto source) {
        if (source == null) {
            return null;
        }
        return new ConfigurationOverride(source.issuerDid(), source.verificationMethod(), source.keyId(), source.keyPin());
    }

    public static CredentialOfferMetadata toCredentialOfferMetadataDto(CredentialOfferMetadataDto dto) {
        if (dto == null) {
            return null;
        }
        return new CredentialOfferMetadata(dto.deferred(), dto.vctIntegrity(), dto.vctMetadataUri(), dto.vctMetadataUriIntegrity());
    }

    public static CredentialOfferMetadataDto toCredentialOfferMetadata(CredentialOfferMetadata metadata) {
        if (metadata == null) {
            return new CredentialOfferMetadataDto(null, null, null, null);
        }
        return new CredentialOfferMetadataDto(metadata.deferred(), metadata.vctIntegrity(), metadata.vctMetadataUri(), metadata.vctMetadataUriIntegrity());
    }

    private static String getCredentialIssuer(ApplicationProperties props, CredentialOffer credential) {

        if (!props.isSignedMetadataEnabled() || isNull(credential.getCredentialManagement().getMetadataTenantId())) {
            return props.getExternalUrl();
        }

        return "%s/%s".formatted(props.getExternalUrl(), credential.getCredentialManagement().getMetadataTenantId());
    }

    private static String getOfferDeeplinkFromCredential(ApplicationProperties props,
                                                         CredentialOffer credentialOffer) {

        var grants = new GrantsDto(new PreAuthorizedCodeGrantDto(credentialOffer.getPreAuthorizedCode()));
        var credentialIssuer = getCredentialIssuer(props, credentialOffer);
        var objectMapper = new ObjectMapper();

        var credentialOfferDto = CredentialOfferDto.builder()
                .credentialIssuer(credentialIssuer)
                .credentials(credentialOffer.getMetadataCredentialSupportedId())
                .grants(grants)
                .build();

        String credentialOfferString;
        try {
            credentialOfferString = URLEncoder.encode(objectMapper.writeValueAsString(credentialOfferDto),
                    Charset.defaultCharset());
        } catch (JsonProcessingException e) {
            throw new JsonException(
                    "Error processing credential offer for credential with id %s".formatted(credentialOffer.getId()), e);
        }

        return String.format("%s://?credential_offer=%s", props.getDeeplinkSchema(),
                credentialOfferString);
    }

    /**
     * Converts a renewal response to a credential offer request.
     *
     * @param request the renewal response
     * @return the converted credential offer request
     */
    public static CreateCredentialOfferRequestDto toOfferFromRenewal(
            RenewalResponseDto request) {
        return CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(request.metadataCredentialSupportedId())
                .credentialSubjectData(request.credentialSubjectData())
                .credentialMetadata(request.credentialMetadata())
                .credentialValidUntil(request.credentialValidUntil())
                .credentialValidFrom(request.credentialValidFrom())
                .statusLists(request.statusLists())
                .build();
    }

    /**
     * Updates an existing CredentialOffer with data from a CreateCredentialOfferRequestDto and supporting parameters.
     *
     * @param existingOffer         the offer to update
     * @param newOffer              the DTO with new data
     * @param offerData             the parsed offer data
     * @param applicationProperties the application properties
     */
    public static void updateOfferFromDto(
            CredentialOffer existingOffer,
            CreateCredentialOfferRequestDto newOffer,
            Map<String, Object> offerData,
            ApplicationProperties applicationProperties) {
        existingOffer.setMetadataCredentialSupportedId(newOffer.getMetadataCredentialSupportedId());
        existingOffer.setOfferData(offerData);
        existingOffer.setCredentialValidFrom(newOffer.getCredentialValidFrom());
        existingOffer.setCredentialValidUntil(newOffer.getCredentialValidUntil());
        existingOffer.setCredentialMetadata(toCredentialOfferMetadataDto(newOffer.getCredentialMetadata()));
        existingOffer.setConfigurationOverride(toConfigurationOverride(newOffer.getConfigurationOverride()));
        existingOffer.getCredentialManagement().setMetadataTenantId(applicationProperties.isSignedMetadataEnabled() ? java.util.UUID.randomUUID() : null);
    }

}