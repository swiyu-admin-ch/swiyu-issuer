package ch.admin.bit.eid.issuer_management.models.mappers;

import ch.admin.bit.eid.issuer_management.models.dto.CredentialWithDeeplinkResponseDto;
import ch.admin.bit.eid.issuer_management.models.dto.UpdateStatusResponseDto;
import ch.admin.bit.eid.issuer_management.models.entities.CredentialOfferEntity;
import lombok.experimental.UtilityClass;

@UtilityClass
public class CredentialOfferMapper {

    public static CredentialWithDeeplinkResponseDto credentialToCredentialResponseDto(CredentialOfferEntity credential,
                                                                                      String offer_deeplinkString) {

        return CredentialWithDeeplinkResponseDto.builder()
                .management_id(credential.getId())
                .offer_deeplink(offer_deeplinkString)
                .build();
    }

    public static Object credentialToCredentialResponseDto(CredentialOfferEntity credential) {
        return credential.getOfferData();
    }

    public static UpdateStatusResponseDto credentialToUpdateStatusResponseDto(CredentialOfferEntity credential) {
        return UpdateStatusResponseDto.builder()
                .id(credential.getId())
                .credential_status(credential.getCredentialStatus().getDisplayName())
                .build();
    }
}
