package ch.admin.bj.swiyu.issuer.oid4vci.test;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import com.google.gson.GsonBuilder;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@UtilityClass
public class CredentialOfferTestData {

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialOfferStatusType status, String metadataId) {
        return createTestOffer(preAuthCode, status, metadataId, Instant.now().minusSeconds(10), Instant.now().plusSeconds(120), null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialOfferStatusType status, String metadataId, ConfigurationOverride override) {
        return createTestOffer(preAuthCode, status, metadataId, Instant.now().minusSeconds(10), Instant.now().plusSeconds(120), null, override, null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialOfferStatusType status, String metadataId, Instant validFrom, Instant validUntil) {
        return createTestOffer(preAuthCode, status, metadataId, validFrom, validUntil, null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialOfferStatusType status, String metadataId, CredentialOfferMetadata metadata) {
        return createTestOffer(preAuthCode, status, metadataId, Instant.now().minusSeconds(10), Instant.now().plusSeconds(120), metadata);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialOfferStatusType status, String metadataId, CredentialOfferMetadata metadata, Integer deferredExpirationInSeconds) {
        return createTestOffer(preAuthCode, status, metadataId, Instant.now().minusSeconds(10), Instant.now().plusSeconds(120), metadata, null, deferredExpirationInSeconds);
    }

    public static StatusList createStatusList() {
        var statusListToken = new TokenStatusListToken(2, 10000);
        return StatusList.builder()
                .config(Map.of("bits", 2))
                .uri("https://localhost:8080/status")
                .statusZipped(statusListToken.getStatusListClaims().get("lst").toString())
                .maxLength(10000)
                .build();
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode,
                                                  CredentialOfferStatusType status,
                                                  String metadataId,
                                                  Instant validFrom,
                                                  Instant validUntil,
                                                  CredentialOfferMetadata credentialMetadata) {
        return createTestOffer(preAuthCode, status, metadataId, validFrom, validUntil, credentialMetadata, null, null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode,
                                                  CredentialOfferStatusType status,
                                                  String metadataId,
                                                  Instant validFrom,
                                                  Instant validUntil,
                                                  CredentialOfferMetadata credentialMetadata,
                                                  ConfigurationOverride override,
                                                  Integer deferredExpirationInSeconds) {
        HashMap<String, Object> offerData = new HashMap<>();
        offerData.put("data", new GsonBuilder().create().toJson(addIllegalClaims(getUniversityCredentialSubjectData())));
        return CredentialOffer.builder()
                .credentialStatus(status)
                .metadataCredentialSupportedId(List.of(metadataId))
                .offerData(offerData)
                .credentialMetadata(credentialMetadata)
                .deferredOfferValiditySeconds(deferredExpirationInSeconds)
                .nonce(UUID.randomUUID())
                .preAuthorizedCode(preAuthCode)
                .offerExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .credentialValidFrom(validFrom)
                .credentialValidUntil(validUntil)
                .configurationOverride(override)
                .build();
    }

    /**
     * illegally overriding some properties. They should be ignored in all tests this is used
     *
     * @param credentialSubjectData the credential subject data to be manipulated
     * @return a new copy of the credentialSubjectData with additional sd-jwt illegal claims
     */
    public static Map<String, String> addIllegalClaims(Map<String, String> credentialSubjectData) {
        var alteredCredentialSubjectData = new HashMap<>(credentialSubjectData);
        alteredCredentialSubjectData.put("iss", "did:example:test-university");
        alteredCredentialSubjectData.put("vct", "lorem ipsum");
        alteredCredentialSubjectData.put("iat", "0");
        return alteredCredentialSubjectData;
    }

    public static Map<String, String> getUniversityCredentialSubjectData() {
        Map<String, String> credentialSubjectData = new HashMap<>();
        credentialSubjectData.put("type", "Bachelor of Science");
        credentialSubjectData.put("name", "Data Science");
        return credentialSubjectData;
    }

    public static CredentialOfferStatus linkStatusList(CredentialOffer offer, StatusList statusList, int index) {
        return new CredentialOfferStatus(
                new CredentialOfferStatusKey(offer.getId(), statusList.getId(), index)
        );
    }
}