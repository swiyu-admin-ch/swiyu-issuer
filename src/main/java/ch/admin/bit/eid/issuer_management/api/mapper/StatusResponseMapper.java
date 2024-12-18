package ch.admin.bit.eid.issuer_management.api.mapper;

import ch.admin.bit.eid.issuer_management.api.dto.StatusResponseDto;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import lombok.experimental.UtilityClass;

@UtilityClass
public class StatusResponseMapper {

    public static StatusResponseDto credentialToStatusResponseDto(CredentialOffer credentialOffer) {

        return StatusResponseDto.builder()
                .status(credentialOffer.getCredentialStatus())
                .build();
    }
}
