/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.StatusResponseDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import lombok.experimental.UtilityClass;


@UtilityClass
public class StatusResponseMapper {

    public static StatusResponseDto toStatusResponseDto(CredentialOffer credentialOffer) {

        return StatusResponseDto.builder()
                .status(toCredentialStatusTypeDto(credentialOffer.getCredentialStatus()))
                .build();
    }

    public static CredentialStatusTypeDto toCredentialStatusTypeDto(CredentialStatusType source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case OFFERED -> CredentialStatusTypeDto.OFFERED;
            case CANCELLED -> CredentialStatusTypeDto.CANCELLED;
            case IN_PROGRESS -> CredentialStatusTypeDto.IN_PROGRESS;
            case DEFERRED -> CredentialStatusTypeDto.DEFERRED;
            case READY -> CredentialStatusTypeDto.READY;
            case ISSUED -> CredentialStatusTypeDto.ISSUED;
            case SUSPENDED -> CredentialStatusTypeDto.SUSPENDED;
            case REVOKED -> CredentialStatusTypeDto.REVOKED;
            case EXPIRED -> CredentialStatusTypeDto.EXPIRED;
        };
    }
}