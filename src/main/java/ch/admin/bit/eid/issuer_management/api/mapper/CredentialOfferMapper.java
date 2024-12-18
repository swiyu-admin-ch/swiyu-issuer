package ch.admin.bit.eid.issuer_management.api.mapper;

import ch.admin.bit.eid.issuer_management.api.dto.CredentialWithDeeplinkResponseDto;
import ch.admin.bit.eid.issuer_management.api.dto.UpdateStatusResponseDto;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import lombok.experimental.UtilityClass;

import java.util.Map;

@UtilityClass
public class CredentialOfferMapper {

    public static CredentialWithDeeplinkResponseDto credentialToCredentialResponseDto(CredentialOffer credential,
                                                                                      String offerDeeplinkString) {

        return CredentialWithDeeplinkResponseDto.builder()
                .managementId(credential.getId())
                .offerDeeplink(offerDeeplinkString)
                .build();
    }

    public static Object credentialToCredentialResponseDto(CredentialOffer credential) {
        Map<String, Object> offerData = credential.getOfferData();
        if (offerData != null && offerData.containsKey("data")) {
            return offerData.get("data");
        }
        return offerData;
    }

    public static UpdateStatusResponseDto credentialToUpdateStatusResponseDto(CredentialOffer credential) {
        return UpdateStatusResponseDto.builder()
                .id(credential.getId())
                .credentialStatus(credential.getCredentialStatus())
                .build();
    }
}
