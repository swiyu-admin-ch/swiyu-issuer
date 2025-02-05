/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service;

import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialStatusType;
import lombok.experimental.UtilityClass;

import java.util.Map;

import static ch.admin.bj.swiyu.issuer.management.service.statusregistry.StatusResponseMapper.toCredentialStatusTypeDto;

@UtilityClass
public class CredentialOfferMapper {

    public static CredentialWithDeeplinkResponseDto toCredentialWithDeeplinkResponseDto(CredentialOffer credential,
                                                                                        String offerDeeplinkString) {

        return CredentialWithDeeplinkResponseDto.builder()
                .managementId(credential.getId())
                .offerDeeplink(offerDeeplinkString)
                .build();
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
            case ISSUED -> CredentialStatusType.ISSUED;
            case SUSPENDED -> CredentialStatusType.SUSPENDED;
            case REVOKED -> CredentialStatusType.REVOKED;
            case EXPIRED -> CredentialStatusType.EXPIRED;
        };
    }
}
