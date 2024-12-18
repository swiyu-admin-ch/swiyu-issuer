package ch.admin.bit.swiyu.issuer.management.api.mapper;

import ch.admin.bit.swiyu.issuer.management.api.dto.CredentialWithDeeplinkResponseDto;
import ch.admin.bit.swiyu.issuer.management.api.dto.UpdateStatusResponseDto;
import ch.admin.bit.swiyu.issuer.management.domain.credential_offer.CredentialOfferEntity;
import lombok.experimental.UtilityClass;

import java.util.Map;

@UtilityClass
public class CredentialOfferMapper {

    public static CredentialWithDeeplinkResponseDto credentialToCredentialResponseDto(CredentialOfferEntity credential,
                                                                                      String offerDeeplinkString) {

        return CredentialWithDeeplinkResponseDto.builder()
                .managementId(credential.getId())
                .offerDeeplink(offerDeeplinkString)
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
                .credentialStatus(credential.getCredentialStatus())
                .build();
    }
}
