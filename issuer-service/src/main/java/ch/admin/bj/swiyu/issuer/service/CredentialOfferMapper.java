/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.ClientAgentInfoDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import lombok.experimental.UtilityClass;

import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.mapper.CredentialRequestMapper.toCredentialRequest;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.StatusResponseMapper.toCredentialStatusTypeDto;

@UtilityClass
public class CredentialOfferMapper {

    public static CredentialWithDeeplinkResponseDto toCredentialWithDeeplinkResponseDto(CredentialOffer credential,
                                                                                        String offerDeeplinkString) {
        return CredentialWithDeeplinkResponseDto.builder()
                .managementId(credential.getId())
                .offerDeeplink(offerDeeplinkString)
                .build();
    }

    public static CredentialInfoResponseDto toCredentialInfoResponseDto(CredentialOffer credential, String offerDeeplinkString) {
        return new CredentialInfoResponseDto(
                toCredentialStatusTypeDto(credential.getCredentialStatus()),
                credential.getMetadataCredentialSupportedId(),
                credential.getCredentialMetadata(),
                credential.getHolderJWKs() != null ? credential.getHolderJWKs() : null,
                toClientAgentInfoDto(credential.getClientAgentInfo()),
                credential.getOfferExpirationTimestamp(),
                credential.getCredentialValidFrom(),
                credential.getCredentialValidUntil(),
                toCredentialRequest(credential.getCredentialRequest()),
                offerDeeplinkString
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
}