/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.experimental.UtilityClass;
import org.springframework.util.CollectionUtils;

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.service.mapper.CredentialRequestMapper.toCredentialRequest;
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
                .offerDeeplink(getOfferDeeplinkFromCredential(props, credentialOffer, management))
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
                !CollectionUtils.isEmpty(credential.getHolderJWKs()) ? credential.getHolderJWKs() : null,
                !CollectionUtils.isEmpty(credential.getKeyAttestations()) ? credential.getKeyAttestations() : null,
                toClientAgentInfoDto(credential.getClientAgentInfo()),
                credential.getOfferExpirationTimestamp(),
                credential.getDeferredOfferValiditySeconds(),
                credential.getCredentialValidFrom(),
                credential.getCredentialValidUntil(),
                toCredentialRequest(credential.getCredentialRequest()),
                getOfferDeeplinkFromCredential(props, credential, credential.getCredentialManagement())
        );
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

    public static CredentialStatusType toCredentialStatusType(CredentialStatusTypeDto source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case OFFERED -> CredentialStatusType.OFFERED;
            case CANCELLED -> CredentialStatusType.CANCELLED;
            case IN_PROGRESS -> CredentialStatusType.IN_PROGRESS;
            case DEFERRED -> CredentialStatusType.DEFERRED;
            case READY -> CredentialStatusType.READY;
            case ISSUED -> CredentialStatusType.ISSUED;
            case SUSPENDED -> CredentialStatusType.SUSPENDED;
            case REVOKED -> CredentialStatusType.REVOKED;
            case EXPIRED -> CredentialStatusType.EXPIRED;
        };
    }

    public static CredentialStatusType toCredentialStatusType(UpdateCredentialStatusRequestTypeDto source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case CANCELLED -> CredentialStatusType.CANCELLED;
            case READY -> CredentialStatusType.READY;
            case ISSUED -> CredentialStatusType.ISSUED;
            case SUSPENDED -> CredentialStatusType.SUSPENDED;
            case REVOKED -> CredentialStatusType.REVOKED;
        };
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

        if (!props.isSignedMetadataEnabled() || isNull(credential.getMetadataTenantId())) {
            return props.getExternalUrl();
        }

        return "%s/%s".formatted(props.getExternalUrl(), credential.getMetadataTenantId());
    }

    private static String getOfferDeeplinkFromCredential(ApplicationProperties props,
                                                         CredentialOffer credentialOffer,
                                                         CredentialManagement mgmt) {

        var grants = new GrantsDto(new PreAuthorizedCodeGrantDto(credentialOffer.getPreAuthorizedCode()));
        var credentialIssuer = getCredentialIssuer(props, credentialOffer);
        var objectMapper = new ObjectMapper();

        var credentialOfferDto = CredentialOfferDto.builder()
                .credentialIssuer(credentialIssuer)
                .credentials(credentialOffer.getMetadataCredentialSupportedId())
                .grants(grants)
                .version(props.getRequestOfferVersion())
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

}