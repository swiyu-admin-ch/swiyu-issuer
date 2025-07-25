/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.test;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import com.google.gson.GsonBuilder;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.nonNull;

@UtilityClass
public class CredentialOfferTestData {

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialStatusType status, String metadataId) {
        return createTestOffer(preAuthCode, status, metadataId, Instant.now().minusSeconds(10), Instant.now().plusSeconds(120), null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialStatusType status, String metadataId, Instant validFrom, Instant validUntil) {
        return createTestOffer(preAuthCode, status, metadataId, validFrom, validUntil, null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialStatusType status, String metadataId, Map<String, Object> metadata) {
        return createTestOffer(preAuthCode, status, metadataId, Instant.now().minusSeconds(10), Instant.now().plusSeconds(120), metadata);
    }

    public static StatusList createStatusList() {
        var statusListToken = new TokenStatusListToken(2, 10000);
        return StatusList.builder().type(StatusListType.TOKEN_STATUS_LIST)
                .config(Map.of("bits", 2))
                .uri("https://localhost:8080/status")
                .statusZipped(statusListToken.getStatusListClaims().get("lst").toString())
                .nextFreeIndex(0)
                .maxLength(10000)
                .build();
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode,
                                                  CredentialStatusType status,
                                                  String metadataId,
                                                  Instant validFrom,
                                                  Instant validUntil,
                                                  Map<String, Object> credentialMetadata) {
        Map<String, Object> defaultCredentialMetadata = Map.of("vct#integrity", "sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=");
        HashMap<String, Object> offerData = new HashMap<>();
        offerData.put("data", new GsonBuilder().create().toJson(addIllegalClaims(getUniversityCredentialSubjectData())));
        return CredentialOffer.builder()
                .credentialStatus(status)
                .metadataCredentialSupportedId(List.of(metadataId))
                .offerData(offerData)
                .credentialMetadata(nonNull(credentialMetadata) ? credentialMetadata : defaultCredentialMetadata)
                .accessToken(UUID.randomUUID())
                .tokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .nonce(UUID.randomUUID())
                .preAuthorizedCode(preAuthCode)
                .offerExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .credentialValidFrom(validFrom)
                .credentialValidUntil(validUntil)
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
        credentialSubjectData.put("degree", "Bachelor of Science");
        credentialSubjectData.put("name", "Data Science");
        credentialSubjectData.put("average_grade", "5.33");
        return credentialSubjectData;
    }

    public static CredentialOfferStatus linkStatusList(CredentialOffer offer, StatusList statusList) {
        return new CredentialOfferStatus(
                new CredentialOfferStatusKey(offer.getId(), statusList.getId()),
                statusList.getNextFreeIndex()
        );
    }
}