package ch.admin.bj.swiyu.issuer.service.management;

import ch.admin.bj.swiyu.issuer.dto.CredentialManagementDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachineConfig;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import lombok.experimental.UtilityClass;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.service.offer.CredentialOfferMapper.toCredentialInfoResponseDtoList;

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
        var status = credentialManagement.getCredentialManagementStatus();
        if (status == null) {
            throw new BadRequestException("Credential management status is null for credential management id: "
                    + credentialManagement.getId());
        }
        if (status == CredentialStatusManagementType.INIT) {
            var offer = credentialManagement.getCredentialOffers().stream().findFirst();
            var credentialStatus = offer.map(CredentialOffer::getCredentialStatus).orElse(null);
            return credentialStatus != null ? CredentialStatusTypeDto.valueOf(credentialStatus.name()) : null;
        }
        return CredentialStatusTypeDto.valueOf(status.name());
    }

    public static CredentialStateMachineConfig.CredentialManagementEvent toCredentialManagementEvent(UpdateCredentialStatusRequestTypeDto source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case ISSUED -> CredentialStateMachineConfig.CredentialManagementEvent.ISSUE;
            case SUSPENDED -> CredentialStateMachineConfig.CredentialManagementEvent.SUSPEND;
            case REVOKED -> CredentialStateMachineConfig.CredentialManagementEvent.REVOKE;
            default -> null; // we don't handle READY, CANCELLED at management level
        };
    }

    public static CredentialStateMachineConfig.CredentialOfferEvent toCredentialOfferEvent(UpdateCredentialStatusRequestTypeDto source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case ISSUED -> CredentialStateMachineConfig.CredentialOfferEvent.ISSUE;
            case READY -> CredentialStateMachineConfig.CredentialOfferEvent.READY;
            case CANCELLED -> CredentialStateMachineConfig.CredentialOfferEvent.CANCEL;
            default -> null; // we don't handle SUSPENDED and REVOKED at offer level
        };
    }

    public static UpdateStatusResponseDto toUpdateStatusResponseDto(CredentialManagement mgmt, @Nullable List<UUID> statusLists) {
        var responseDto = UpdateStatusResponseDto.builder()
                .id(mgmt.getId())
                .credentialStatus(toCredentialStatusTypeDto(mgmt))
                .build();

        if (statusLists != null && !statusLists.isEmpty()) {
            responseDto.setStatusLists(statusLists);
        }

        return responseDto;
    }
}