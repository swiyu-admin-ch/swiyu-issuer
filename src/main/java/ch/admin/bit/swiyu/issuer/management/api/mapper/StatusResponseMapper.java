package ch.admin.bit.swiyu.issuer.management.api.mapper;

import ch.admin.bit.swiyu.issuer.management.api.dto.StatusResponseDto;
import ch.admin.bit.swiyu.issuer.management.domain.credential_offer.CredentialOfferEntity;
import lombok.experimental.UtilityClass;

@UtilityClass
public class StatusResponseMapper {

    public static StatusResponseDto credentialToStatusResponseDto(CredentialOfferEntity credentialOffer) {

        return StatusResponseDto.builder()
                .status(credentialOffer.getCredentialStatus())
                .build();
    }
}
