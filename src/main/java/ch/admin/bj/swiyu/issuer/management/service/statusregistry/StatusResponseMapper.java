package ch.admin.bj.swiyu.issuer.management.service.statusregistry;

import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.StatusResponseDto;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOffer;
import lombok.experimental.UtilityClass;

@UtilityClass
public class StatusResponseMapper {

    public static StatusResponseDto toStatusResponseDto(CredentialOffer credentialOffer) {

        return StatusResponseDto.builder()
                .status(credentialOffer.getCredentialStatus())
                .build();
    }
}
