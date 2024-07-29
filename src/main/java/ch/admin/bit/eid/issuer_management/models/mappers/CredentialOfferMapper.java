package ch.admin.bit.eid.issuer_management.models.mappers;

import ch.admin.bit.eid.issuer_management.models.dto.CredentialWithDeeplinkResponseDto;
import ch.admin.bit.eid.issuer_management.models.dto.UpdateStatusResponseDto;
import ch.admin.bit.eid.issuer_management.models.entities.CredentialOfferEntity;
import lombok.experimental.UtilityClass;

import java.util.Map;

@UtilityClass
public class CredentialOfferMapper {

    public static CredentialWithDeeplinkResponseDto credentialToCredentialResponseDto(CredentialOfferEntity credential,
                                                                                      String offerDeeplinkString) {

        return CredentialWithDeeplinkResponseDto.builder()
                .management_id(credential.getId())
                .offer_deeplink(offerDeeplinkString)
                .build();
    }

    public static Object credentialToCredentialResponseDto(CredentialOfferEntity credential) {
        Map<String, Object> offerData = credential.getOfferData();
        if (offerData != null && offerData.containsKey("data")) {
            return offerData.get("data");
        }
        return offerData;
    }

    public static UpdateStatusResponseDto credentialToUpdateStatusResponseDto(CredentialOfferEntity credential) {
        return UpdateStatusResponseDto.builder()
                .id(credential.getId())
                .credentialStatus(credential.getCredentialStatus().getDisplayName())
                .build();
    }
}
