/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.service.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.*;

import static java.time.Instant.now;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class CredentialServiceTest {
    private final Map<String, Object> offerData = Map.of("hello", "world");
    @Mock
    CredentialOfferRepository credentialOfferRepository;
    CredentialService credentialService;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    private StatusListService statusListService;
    private ApplicationProperties applicationProperties;
    private WebhookService webhookService;
    private CredentialOffer expiredOffer;
    private CredentialOffer expiredInProgress;
    private CredentialOffer valid;
    private CredentialOffer issued;
    private CredentialOffer suspended;

    @BeforeEach
    void setUp() {
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        statusListService = Mockito.mock(StatusListService.class);
        KeyAttestationService keyAttestationService = Mockito.mock(KeyAttestationService.class);
        IssuerMetadataTechnical issuerMetadata = Mockito.mock(IssuerMetadataTechnical.class);
        CredentialFormatFactory credentialFormatFactory = Mockito.mock(CredentialFormatFactory.class);
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        OpenIdIssuerConfiguration openIdIssuerConfiguration = Mockito.mock(OpenIdIssuerConfiguration.class);
        DataIntegrityService dataIntegrityService = Mockito.mock(DataIntegrityService.class);
        webhookService = Mockito.mock(WebhookService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);

        expiredOffer = getCredentialOffer(CredentialStatusType.OFFERED, now().minusSeconds(1).getEpochSecond(), offerData);
        expiredInProgress = getCredentialOffer(CredentialStatusType.IN_PROGRESS, now().minusSeconds(1).getEpochSecond(), offerData);
        valid = getCredentialOffer(CredentialStatusType.OFFERED, now().plusSeconds(1000).getEpochSecond(), offerData);
        suspended = getCredentialOffer(CredentialStatusType.SUSPENDED, now().plusSeconds(1000).getEpochSecond(), offerData);
        issued = getCredentialOffer(CredentialStatusType.ISSUED, now().minusSeconds(1).getEpochSecond(), null);

        when(credentialOfferRepository.findById(expiredOffer.getId())).thenReturn(Optional.of(expiredOffer));
        when(credentialOfferRepository.findById(expiredInProgress.getId())).thenReturn(Optional.of(expiredInProgress));
        when(credentialOfferRepository.findById(valid.getId())).thenReturn(Optional.of(valid));
        when(credentialOfferRepository.findById(issued.getId())).thenReturn(Optional.of(issued));
        when(credentialOfferRepository.findById(suspended.getId())).thenReturn(Optional.of(suspended));

        when(credentialOfferRepository.findByIdForUpdate(expiredOffer.getId())).thenReturn(Optional.of(expiredOffer));
        when(credentialOfferRepository.findByIdForUpdate(expiredInProgress.getId())).thenReturn(Optional.of(expiredInProgress));
        when(credentialOfferRepository.findByIdForUpdate(valid.getId())).thenReturn(Optional.of(valid));
        when(credentialOfferRepository.findByIdForUpdate(issued.getId())).thenReturn(Optional.of(issued));
        when(credentialOfferRepository.findByIdForUpdate(suspended.getId())).thenReturn(Optional.of(suspended));

        when(credentialOfferRepository.save(expiredOffer)).thenReturn(expiredOffer);
        when(credentialOfferRepository.save(expiredInProgress)).thenReturn(expiredInProgress);
        when(credentialOfferRepository.save(valid)).thenReturn(valid);
        when(credentialOfferRepository.save(issued)).thenReturn(issued);
        when(credentialOfferRepository.save(suspended)).thenReturn(suspended);

        credentialService = new CredentialService(
                credentialOfferRepository,
                credentialOfferStatusRepository,
                new ObjectMapper(),
                statusListService,
                keyAttestationService,
                issuerMetadata,
                credentialFormatFactory,
                applicationProperties,
                openIdIssuerConfiguration,
                dataIntegrityService,
                webhookService
        );
    }

    @Test
    void offerDeeplinkTest() {
        var validDeeplink = credentialService.getCredentialOfferDeeplink(valid.getId());

        // THEN
        assertThat(validDeeplink).isNotNull();
        System.out.println(validDeeplink);
        assertTrue(validDeeplink.contains("version"));
        assertTrue(validDeeplink.contains("credential_offer="));
        assertTrue(validDeeplink.contains("grant-type"));
        assertTrue(validDeeplink.contains("pre-authorized_code"));
    }

    @Test
    void getCredentialInvalidateOfferWhenExpired() {

        // note: getting an expired offer will immediately update it to expired
        var expiredOfferId = expiredOffer.getId();
        var response = credentialService.getCredentialOffer(expiredOfferId);

        Mockito.verify(credentialOfferRepository, Mockito.times(1)).findByIdForUpdate(expiredOfferId);
        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(any());

        // offer data should be null after expiration therefore no offer data or deeplink should be returned
        assertNull(response);

        var statusResponse = credentialService.getCredentialStatus(expiredOfferId);

        assertEquals(CredentialStatusTypeDto.EXPIRED, statusResponse.getStatus());
    }

    @Test
    void getDeeplinkInvalidateOfferWhenExpired() {

        when(applicationProperties.getDeeplinkSchema()).thenReturn("swiyu");

        var deepLink = credentialService.getCredentialOfferDeeplink(valid.getId());

        assertNotNull(deepLink);
        assertTrue(deepLink.startsWith("swiyu://"));
    }

    @Test
    void getCredentialOfferWhenNotExpired_thenSuccess() {

        Map<String, String> response = (Map<String, String>) credentialService.getCredentialOffer(valid.getId());

        assertNotNull(response);
        assertEquals(offerData.get("hello"), response.get("hello"));

        credentialService.getCredentialOfferDeeplink(valid.getId());
    }

    @Test
    void updateCredentialStatus_shouldUpdateStatusToRevoked() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferStatusId(issued.getId())).thenReturn(offerStatusSet);

        Mockito.doNothing().when(statusListService).revoke(offerStatusSet);

        var updated = credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.REVOKED);

        assertEquals(CredentialStatusTypeDto.REVOKED, updated.getCredentialStatus());
        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(issued);
        Mockito.verify(webhookService, Mockito.times(1)).produceStateChangeEvent(issued.getId(), CredentialStatusType.REVOKED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CANCELLED", "REVOKED"})
    void updateCredentialStatus_shouldThrowIfStatusIsTerminal(String type) {

        var offer = getCredentialOffer(CredentialStatusType.EXPIRED, now().plusSeconds(1000).getEpochSecond(), offerData);
        var offerId = offer.getId();

        when(credentialOfferRepository.findByIdForUpdate(offer.getId())).thenReturn(Optional.of(offer));

        assertThrows(BadRequestException.class, () ->
                credentialService.updateCredentialStatus(offerId, UpdateCredentialStatusRequestTypeDto.valueOf(type))
        );
    }

    @Test
    void updateCredentialStatus_shouldNotUpdateIfStatusUnchanged() {
        credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.ISSUED);

        Mockito.verify(credentialOfferRepository, Mockito.never()).save(any());
    }

    @Test
    void givenExpiredToken_whenGetCredential_thenThrowOAuthException() throws OAuthException {
        // Given
        var uuid = UUID.randomUUID();

        var expirationTimeStamp = now().plusSeconds(1000).getEpochSecond();
        var offer = getCredentialOffer(CredentialStatusType.IN_PROGRESS, expirationTimeStamp, offerData, uuid, uuid, UUID.randomUUID());
        offer.setTokenExpirationTimestamp(Instant.now().minusSeconds(600).getEpochSecond());

        when(credentialOfferRepository.findByAccessToken(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var credentialRequestDto = new CredentialRequestDto(
                "vc+sd-jwt",
                new HashMap<>(),
                null
        );
        var ex = assertThrows(OAuthException.class, () -> credentialService.createCredential(credentialRequestDto, uuid.toString()));

        // THEN Status is changed and offer data is cleared
        assertEquals("INVALID_REQUEST", ex.getError().toString());
        assertEquals("AccessToken expired.", ex.getMessage());
    }

    @Test
    void givenExpiredOffer_whenCredentialIsCreated_throws() {
        // GIVEN
        var uuid = UUID.randomUUID();
        var preAuthorizedCode = UUID.randomUUID();

        var expirationTimeStamp = Instant.now().minusSeconds(10).getEpochSecond();
        var offer = getCredentialOffer(CredentialStatusType.OFFERED, expirationTimeStamp, offerData, uuid, preAuthorizedCode, UUID.randomUUID());

        when(credentialOfferRepository.findByAccessToken(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var credentialRequestDto = new CredentialRequestDto(
                "vc+sd-jwt",
                new HashMap<>(),
                null
        );
        var ex = assertThrows(OAuthException.class, () -> credentialService.createCredential(credentialRequestDto, uuid.toString()));

        // THEN Status is changed and offer data is cleared
        assertEquals(CredentialStatusType.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
        assertEquals("INVALID_TOKEN", ex.getError().toString());
        assertEquals("Invalid accessToken", ex.getMessage());
    }

    @Test
    void givenExpiredOffer_whenTokenIsCreated_throws() {
        var uuid = UUID.randomUUID();
        var expirationTimeStamp = Instant.now().minusSeconds(10).getEpochSecond();
        var offer = getCredentialOffer(CredentialStatusType.OFFERED, expirationTimeStamp, offerData, uuid, uuid, UUID.randomUUID());

        when(credentialOfferRepository.findByPreAuthorizedCode(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var ex = assertThrows(OAuthException.class, () -> credentialService.issueOAuthToken(uuid.toString()));

        // THEN Status is changed and offer data is cleared
        assertEquals(CredentialStatusType.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
        assertEquals("INVALID_GRANT", ex.getError().toString());
        assertEquals("Invalid preAuthCode", ex.getMessage());
    }

    @Test
    void testHandlePostIssuanceStatusChangeRevoked_thenCallCorrectFunction() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferStatusId(issued.getId())).thenReturn(offerStatusSet);

        Mockito.doNothing().when(statusListService).revoke(offerStatusSet);

        credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.REVOKED);

        Mockito.verify(statusListService, Mockito.times(1)).revoke(offerStatusSet);
    }

    @Test
    void testHandlePostIssuanceStatusChangeSuspended_thenCallCorrectFunction() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferStatusId(issued.getId())).thenReturn(offerStatusSet);

        Mockito.doNothing().when(statusListService).revoke(offerStatusSet);

        credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.SUSPENDED);

        Mockito.verify(statusListService, Mockito.times(1)).suspend(offerStatusSet);
    }

    @Test
    void testHandlePostIssuanceStatusChangeIssued_thenCallCorrectFunction() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferStatusId(suspended.getId())).thenReturn(offerStatusSet);

        Mockito.doNothing().when(statusListService).revoke(offerStatusSet);

        credentialService.updateCredentialStatus(suspended.getId(), UpdateCredentialStatusRequestTypeDto.ISSUED);

        Mockito.verify(statusListService, Mockito.times(1)).revalidate(offerStatusSet);
    }

//    @Test
//    void testCreateCredentialOffer_checkExpiration() {
//
//        CreateCredentialRequestDto dto = CreateCredentialRequestDto.builder()
//                .metadataCredentialSupportedId(List.of("test"))
//                .credentialSubjectData(offerData)
//                .offerValiditySeconds(3600)
//                .build();
//
//        credentialService.createCredential(dto);
//
//        // Check that the offer is created with the correct expiration time
//        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(any(CredentialOffer.class));
//        Mockito.verify(webhookService, Mockito.times(1)).produceStateChangeEvent(any(UUID.class), any(CredentialStatusType.class));
//
//        // Verify that the offer expiration timestamp is set correctly
//        var createdOffer = credentialOfferRepository.findByIdForUpdate(any(UUID.class)).orElseThrow();
//        assertTrue(createdOffer.getOfferExpirationTimestamp() > Instant.now().getEpochSecond());
//    }

    private @NotNull Set<CredentialOfferStatus> getCredentialOfferStatusSet() {
        return Set.of(
                CredentialOfferStatus.builder()
                        .id(new CredentialOfferStatusKey(issued.getId(), UUID.randomUUID()))
                        .index(1)
                        .build()
        );
    }

    private CredentialOffer getCredentialOffer(CredentialStatusType statusType, long offerExpirationTimestamp, Map<String, Object> offerData) {

        return getCredentialOffer(statusType, offerExpirationTimestamp, offerData, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
    }

    private CredentialOffer getCredentialOffer(CredentialStatusType status, long offerExpirationTimestamp, Map<String, Object> offerData, UUID accessToken, UUID preAuthorizedCode, UUID nonce) {

        return new CredentialOffer(
                UUID.randomUUID(),
                status,
                Collections.emptyList(),
                offerData,
                new HashMap<>(),
                accessToken,
                null,
                null,
                Instant.now().plusSeconds(600).getEpochSecond(),
                nonce,
                preAuthorizedCode,
                offerExpirationTimestamp,
                Instant.now(),
                Instant.now(),
                null
        );
    }


//    private CredentialOffer invokeUpdateCredentialStatus(CredentialOffer offer, CredentialStatusType newStatus) {
//        try {
//            var method = CredentialService.class.getDeclaredMethod("updateCredentialStatus", CredentialOffer.class, CredentialStatusType.class);
//            method.setAccessible(true);
//            return (CredentialOffer) method.invoke(credentialService, offer, newStatus);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }

}