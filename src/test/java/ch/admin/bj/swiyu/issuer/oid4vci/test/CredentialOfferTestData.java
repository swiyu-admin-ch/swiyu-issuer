/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.test;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.*;
import com.google.gson.GsonBuilder;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.util.*;

import static java.util.Objects.nonNull;

@UtilityClass
public class CredentialOfferTestData {

    public static CredentialOffer createTestOffer(UUID offerID, UUID preAuthCode, CredentialStatusType status, String metadataId) {
        return createTestOffer(offerID, preAuthCode, status, metadataId, Instant.now(), Instant.now().plusSeconds(120), null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialStatusType status, String metadataId) {
        return createTestOffer(UUID.randomUUID(), preAuthCode, status, metadataId, Instant.now(), Instant.now().plusSeconds(120), null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialStatusType status, String metadataId, Instant validFrom, Instant validUntil) {
        return createTestOffer(UUID.randomUUID(), preAuthCode, status, metadataId, validFrom, validUntil, null);
    }

    public static CredentialOffer createTestOffer(UUID preAuthCode, CredentialStatusType status, String metadataId, Instant validFrom, Instant validUntil, Map<String, Object> credentialMetadata) {
        return createTestOffer(UUID.randomUUID(), preAuthCode, status, metadataId, validFrom, validUntil, credentialMetadata);
    }

    public static StatusList createStatusList() {
        var statusListToken = new TokenStatusListToken(2, 10000);
        return new StatusList(
                UUID.randomUUID(),
                StatusListType.TOKEN_STATUS_LIST,
                Map.of("bits", 2),
                "https://localhost:8080/status",
                statusListToken.getStatusListClaims().get("lst").toString(),
                0,
                10000,
                Collections.emptySet()

        );
    }

    public static CredentialOffer createTestOffer(UUID offerID,
                                                  UUID preAuthCode,
                                                  CredentialStatusType status,
                                                  String metadataId,
                                                  Instant validFrom,
                                                  Instant validUntil,
                                                  Map<String, Object> credentialMetadata) {
        Map<String, Object> defaultCredentialMetadata = Map.of("vct#integrity", "sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=");
        HashMap<String, Object> offerData = new HashMap<>();
        offerData.put("data", new GsonBuilder().create().toJson(addIllegalClaims(getUniversityCredentialSubjectData())));
        return new CredentialOffer(
                offerID,
                status,
                List.of(metadataId),
                offerData,
                nonNull(credentialMetadata) ? credentialMetadata : defaultCredentialMetadata,
                UUID.randomUUID(),
                null,
                null,
                Instant.now().plusSeconds(600).getEpochSecond(),
                UUID.randomUUID(),
                preAuthCode,
                Instant.now().plusSeconds(120).getEpochSecond(),
                validFrom,
                validUntil,
                null,
                null
        );
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
                offer,
                statusList,
                statusList.getNextFreeIndex()
        );
    }
}