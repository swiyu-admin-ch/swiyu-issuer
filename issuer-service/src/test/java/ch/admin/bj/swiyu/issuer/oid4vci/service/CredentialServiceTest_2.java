/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.service.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static java.time.Instant.now;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;

class CredentialServiceTest_2 {
    private final Map<String, Object> offerData = Map.of("hello", "world");
    @Mock
    CredentialOfferRepository credentialOfferRepository;
    CredentialService credentialService;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    private StatusListService statusListService;
    private KeyAttestationService keyAttestationService;
    private IssuerMetadataTechnical issuerMetadata;
    private CredentialFormatFactory credentialFormatFactory;
    private ApplicationProperties applicationProperties;
    private OpenIdIssuerConfiguration openIdIssuerConfiguration;
    private DataIntegrityService dataIntegrityService;
    private WebhookService webhookService;
    private CredentialOffer expiredOffer;
    private CredentialOffer expiredInProgress;
    private CredentialOffer valid;
    private CredentialOffer issued;
    private CredentialOffer expired;


    private CredentialOffer getCredentialOffer(CredentialStatusType statusType, long offerExpirationTimestamp, Map<String, Object> offerData) {
        return CredentialOffer.builder()
                .credentialStatus(statusType)
                .offerExpirationTimestamp(offerExpirationTimestamp)
                .accessToken(UUID.randomUUID())
                .nonce(UUID.randomUUID())
                .offerData(offerData)
                // Note: Issued entries should have their data deleted by the VC signer component
                .build();
    }

    @BeforeEach
    void setUp() {
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        statusListService = Mockito.mock(StatusListService.class);
        keyAttestationService = Mockito.mock(KeyAttestationService.class);
        issuerMetadata = Mockito.mock(IssuerMetadataTechnical.class);
        credentialFormatFactory = Mockito.mock(CredentialFormatFactory.class);
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        openIdIssuerConfiguration = Mockito.mock(OpenIdIssuerConfiguration.class);
        dataIntegrityService = Mockito.mock(DataIntegrityService.class);
        webhookService = Mockito.mock(WebhookService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);

        expiredOffer = getCredentialOffer(CredentialStatusType.OFFERED, now().minusSeconds(1).getEpochSecond(), offerData);
        expiredInProgress = getCredentialOffer(CredentialStatusType.IN_PROGRESS, now().minusSeconds(1).getEpochSecond(), offerData);
        valid = getCredentialOffer(CredentialStatusType.OFFERED, now().plusSeconds(1000).getEpochSecond(), offerData);
        expired = getCredentialOffer(CredentialStatusType.EXPIRED, now().plusSeconds(1000).getEpochSecond(), offerData);
        issued = getCredentialOffer(CredentialStatusType.ISSUED, now().minusSeconds(1).getEpochSecond(), null);

        Mockito.when(credentialOfferRepository.findById(expiredOffer.getId())).thenReturn(Optional.of(expiredOffer));
        Mockito.when(credentialOfferRepository.findById(expiredInProgress.getId())).thenReturn(Optional.of(expiredInProgress));
        Mockito.when(credentialOfferRepository.findById(valid.getId())).thenReturn(Optional.of(valid));
        Mockito.when(credentialOfferRepository.findById(issued.getId())).thenReturn(Optional.of(issued));
        Mockito.when(credentialOfferRepository.findById(expired.getId())).thenReturn(Optional.of(expired));

        Mockito.when(credentialOfferRepository.findByIdForUpdate(expiredOffer.getId())).thenReturn(Optional.of(expiredOffer));
        Mockito.when(credentialOfferRepository.findByIdForUpdate(expiredInProgress.getId())).thenReturn(Optional.of(expiredInProgress));
        Mockito.when(credentialOfferRepository.findByIdForUpdate(valid.getId())).thenReturn(Optional.of(valid));
        Mockito.when(credentialOfferRepository.findByIdForUpdate(issued.getId())).thenReturn(Optional.of(issued));
        Mockito.when(credentialOfferRepository.findByIdForUpdate(expired.getId())).thenReturn(Optional.of(expired));

        Mockito.when(credentialOfferRepository.save(expiredOffer)).thenReturn(expiredOffer);
        Mockito.when(credentialOfferRepository.save(expiredInProgress)).thenReturn(expiredInProgress);
        Mockito.when(credentialOfferRepository.save(valid)).thenReturn(valid);
        Mockito.when(credentialOfferRepository.save(issued)).thenReturn(issued);

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

        Mockito.when(applicationProperties.getDeeplinkSchema()).thenReturn("swiyu");

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

        Set<CredentialOfferStatus> offerStatusSet = Set.of(
                CredentialOfferStatus.builder()
                        .id(new CredentialOfferStatusKey(issued.getId(), UUID.randomUUID()))
                        .index(1)
                        .build()
        );

        Mockito.when(credentialOfferStatusRepository.findByOfferStatusId(issued.getId())).thenReturn(offerStatusSet);

        Mockito.doNothing().when(statusListService).revoke(offerStatusSet);

        var updated = credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.REVOKED);

        assertEquals(CredentialStatusTypeDto.REVOKED, updated.getCredentialStatus());
        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(issued);
        Mockito.verify(webhookService, Mockito.times(1)).produceStateChangeEvent(issued.getId(), CredentialStatusType.REVOKED);
    }

    @Test
    void updateCredentialStatus_shouldThrowIfStatusIsTerminal() {
        var expiredId = expired.getId();
        assertThrows(BadRequestException.class, () ->
                credentialService.updateCredentialStatus(expiredId, UpdateCredentialStatusRequestTypeDto.REVOKED)
        );
    }

    @Test
    void updateCredentialStatus_shouldNotUpdateIfStatusUnchanged() {
        credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.ISSUED);

        Mockito.verify(credentialOfferRepository, Mockito.never()).save(any());
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