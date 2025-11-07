package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockStatic;

class CredentialOfferTest {
    @Test
    void testBuilderAndStatusChange() {
        CredentialOffer offer = CredentialOffer.builder()
                .credentialStatus(CredentialStatusType.OFFERED)
                .metadataCredentialSupportedId(List.of("id1"))
                .offerExpirationTimestamp(Instant.now().plusSeconds(10).getEpochSecond())
                .build();

        assertEquals(CredentialStatusType.OFFERED, offer.getCredentialStatus());
        offer.changeStatus(CredentialStatusType.EXPIRED);
        assertEquals(CredentialStatusType.EXPIRED, offer.getCredentialStatus());
    }

    @Test
    void testHasExpirationTimeStampPassed() {
        CredentialOffer offer = CredentialOffer.builder()
                .offerExpirationTimestamp(Instant.now().minusSeconds(10).getEpochSecond())
                .build();
        assertTrue(offer.hasCredentialOfferExpirationTimestampPassed());
    }

    @Test
    void testReadOfferDataStringAndMap() {
        String jwt = "jwt-data";
        Map<String, Object> result = CredentialOffer.readOfferData(jwt);
        assertEquals("jwt-data", result.get("data"));
        assertEquals("jwt", result.get("data_integrity"));

        Map<String, Object> inputMap = Map.of("key", "value");
        Map<String, Object> resultMap = CredentialOffer.readOfferData(inputMap);
        assertTrue(resultMap.get("data").toString().contains("key"));
    }

    @Test
    void testReadOfferDataUnsupportedType() {
        assertThrows(BadRequestException.class, () -> CredentialOffer.readOfferData(123));
    }

    @Test
    void testExpireAndCancel() {
        CredentialOffer offer = CredentialOffer.builder()
                .offerData(Map.of("data", "test"))
                .credentialStatus(CredentialStatusType.OFFERED)
                .build();
        offer.expire();
        assertEquals(CredentialStatusType.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());

        offer = CredentialOffer.builder()
                .offerData(Map.of("data", "test"))
                .credentialStatus(CredentialStatusType.OFFERED)
                .build();
        offer.cancel();
        assertEquals(CredentialStatusType.CANCELLED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
    }

    @Test
    void testMarkAsIssued() {
        CredentialOffer offer = CredentialOffer.builder()
                .metadataCredentialSupportedId(List.of("supportedId"))
                .offerData(Map.of("data", "test"))
                .credentialStatus(CredentialStatusType.OFFERED)
                .build();
        offer.markAsIssued();
        assertEquals(CredentialStatusType.ISSUED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
    }

    @Test
    void testMarkAsDeferred_withDefaultValue() {
        var transactionId = UUID.randomUUID();
        var credentialRequest = new CredentialRequestClass();
        var holderPublicKeys = List.of("publicKey1", "publicKey2");
        var keyAttestationJwts = List.of("attestation1", "attestation2");
        var clientAgentInfo = new ClientAgentInfo("addr", "agent", "lang", "enc");
        var applicationProperties = Mockito.mock(ApplicationProperties.class);
        Mockito.when(applicationProperties.getDeferredOfferValiditySeconds()).thenReturn(99);

        CredentialOffer offer = CredentialOffer.builder()
                .metadataCredentialSupportedId(List.of("supportedId"))
                .offerData(Map.of("data", "test"))
                .offerExpirationTimestamp(Instant.now().plusSeconds(1000).getEpochSecond())
                .credentialStatus(CredentialStatusType.OFFERED)
                .deferredOfferValiditySeconds(null)
                .build();

        String instantExpected = "2025-01-01T00:00:00.00Z";
        Clock clock = Clock.fixed(Instant.parse(instantExpected), ZoneId.of("UTC"));
        Instant instant = Instant.now(clock);

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now).thenReturn(instant);

            offer.markAsDeferred(transactionId, credentialRequest, holderPublicKeys, keyAttestationJwts, clientAgentInfo, applicationProperties);
            assertEquals(CredentialStatusType.DEFERRED, offer.getCredentialStatus());
            assertEquals(transactionId, offer.getTransactionId());
            assertEquals(credentialRequest, offer.getCredentialRequest());
            assertEquals(holderPublicKeys, offer.getHolderJWKs());
            assertEquals(clientAgentInfo, offer.getClientAgentInfo());
            assertEquals(keyAttestationJwts, offer.getKeyAttestations());
            assertEquals(Instant.now().plusSeconds(99L).getEpochSecond(), offer.getOfferExpirationTimestamp());
        }
    }

    @Test
    void testMarkAsDeferred_withDynamicValue() {
        var transactionId = UUID.randomUUID();
        var credentialRequest = new CredentialRequestClass();
        var holderPublicKeys = List.of("publicKey1", "publicKey2");
        var keyAttestationJwts = List.of("attestation1", "attestation2");
        var clientAgentInfo = new ClientAgentInfo("addr", "agent", "lang", "enc");
        var applicationProperties = Mockito.mock(ApplicationProperties.class);
        Mockito.when(applicationProperties.getDeferredOfferValiditySeconds()).thenReturn(99);

        CredentialOffer offer = CredentialOffer.builder()
                .metadataCredentialSupportedId(List.of("supportedId"))
                .offerData(Map.of("data", "test"))
                .offerExpirationTimestamp(Instant.now().plusSeconds(1000).getEpochSecond())
                .credentialStatus(CredentialStatusType.OFFERED)
                .deferredOfferValiditySeconds(10)
                .build();

        String instantExpected = "2025-01-01T00:00:00Z";
        Clock clock = Clock.fixed(Instant.parse(instantExpected), ZoneId.of("UTC"));
        Instant instant = Instant.now(clock);

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now).thenReturn(instant);

            offer.markAsDeferred(transactionId, credentialRequest, holderPublicKeys, keyAttestationJwts, clientAgentInfo, applicationProperties);
            assertEquals(Instant.now().plusSeconds(10L).getEpochSecond(), offer.getOfferExpirationTimestamp());
        }
    }

    @Test
    void testGetConfigurationOverrideReturnsDefaultIfNull() {
        CredentialOffer offer = CredentialOffer.builder().build();
        assertNotNull(offer.getConfigurationOverride());
    }
}