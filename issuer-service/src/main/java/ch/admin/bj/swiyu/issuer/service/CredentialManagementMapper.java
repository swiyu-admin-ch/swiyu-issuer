package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.CredentialManagementDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import lombok.experimental.UtilityClass;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.service.CredentialOfferMapper.toCredentialInfoResponseDtoList;
import static java.util.Objects.isNull;

@UtilityClass
public class CredentialManagementMapper {

    public static CredentialManagementDto toCredentialManagementDto(ApplicationProperties props,
                                                                    CredentialManagement credentialManagement,
                                                                    Set<CredentialOffer> credentialOffers
    ) {
        return new CredentialManagementDto(
                credentialManagement.getId(),
                toCredentialStatusTypeDto(credentialManagement),
                credentialManagement.getRenewalRequestCnt(),
                credentialManagement.getRenewalResponseCnt(),
                toCredentialInfoResponseDtoList(props, credentialOffers)
        );
    }

    public static CredentialStatusTypeDto toCredentialStatusTypeDto(CredentialManagement credentialManagement) {
        if (credentialManagement.getCredentialManagementStatus() != null) {
            return CredentialStatusTypeDto.valueOf(credentialManagement.getCredentialManagementStatus().name());
        }

        // TODO check all
        var credentialStatus = credentialManagement.getCredentialOffers().stream()
                .findFirst()
                .map(CredentialOffer::getCredentialStatus)
                .orElse(null);

        if (isNull(credentialStatus)) {
            return null;
        }

        return CredentialStatusTypeDto.valueOf(credentialStatus.name());
    }

    public static CredentialStatusManagementType toCredentialStatusManagementType(UpdateCredentialStatusRequestTypeDto statusRequestTypeDto) {
        return CredentialStatusManagementType.valueOf(statusRequestTypeDto.name());
    }

    public static UpdateStatusResponseDto toUpdateStatusResponseDto(CredentialManagement mgmt) {
        return UpdateStatusResponseDto.builder()
                .id(mgmt.getId())
                .credentialStatus(toCredentialStatusTypeDto(mgmt))
                .build();
    }

    public static UpdateStatusResponseDto toUpdateStatusResponseDto(CredentialManagement mgmt, List<UUID> statusLists) {
        return UpdateStatusResponseDto.builder()
                .id(mgmt.getId())
                .credentialStatus(toCredentialStatusTypeDto(mgmt))
                .statusLists(statusLists)
                .build();
    }
}