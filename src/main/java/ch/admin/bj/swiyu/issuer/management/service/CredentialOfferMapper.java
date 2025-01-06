package ch.admin.bj.swiyu.issuer.management.service;

import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOffer;
import lombok.experimental.UtilityClass;

import java.util.Map;

@UtilityClass
public class CredentialOfferMapper {

    public static CredentialWithDeeplinkResponseDto toCredentialWithDeeplinkResponseDto(CredentialOffer credential,
                                                                                        String offerDeeplinkString) {

        return CredentialWithDeeplinkResponseDto.builder()
                .managementId(credential.getId())
                .offerDeeplink(offerDeeplinkString)
                .build();
    }

    public static Object toCredentialWithDeeplinkResponseDto(CredentialOffer credential) {
        Map<String, Object> offerData = credential.getOfferData();
        if (offerData != null && offerData.containsKey("data")) {
            return offerData.get("data");
        }
        return offerData;
    }

    public static UpdateStatusResponseDto toUpdateStatusResponseDto(CredentialOffer credential) {
        return UpdateStatusResponseDto.builder()
                .id(credential.getId())
                .credentialStatus(credential.getCredentialStatus())
                .build();
    }
}
