package ch.admin.bit.eid.issuer_management.models.mappers;

import ch.admin.bit.eid.issuer_management.models.dto.StatusResponseDto;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import lombok.experimental.UtilityClass;

@UtilityClass
public class StatusResponseMapper {

    public static StatusResponseDto credentialToStatusResponseDto(CredentialOffer credentialOffer) {

        return StatusResponseDto.builder()
                .status(credentialOffer.getCredentialStatus().getDisplayName())
                .build();
    }
}
