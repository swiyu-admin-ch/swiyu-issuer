/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialClaim;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.service.webhook.StateChangeEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Instant;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils.getCredentialOffer;
import static java.time.Instant.now;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialManagementServiceTest {
    private final Map<String, Object> offerData = Map.of("hello", "world");
    @Mock
    CredentialOfferRepository credentialOfferRepository;
    CredentialManagementService credentialService;
    @Mock
    ApplicationEventPublisher applicationEventPublisher;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    private StatusListService statusListService;
    private ApplicationProperties applicationProperties;
    private IssuerMetadataTechnical issuerMetadata;
    private DataIntegrityService dataIntegrityService;
    private CredentialOffer expiredOffer;
    private CredentialOffer valid;
    private CredentialOffer issued;
    private CredentialOffer suspended;
    private StatusList statusList;
    private CreateCredentialRequestDto createCredentialRequestDto;

    @BeforeEach
    void setUp() {
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        statusListService = Mockito.mock(StatusListService.class);
        issuerMetadata = Mockito.mock(IssuerMetadataTechnical.class);
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        dataIntegrityService = Mockito.mock(DataIntegrityService.class);
        applicationEventPublisher = Mockito.mock(ApplicationEventPublisher.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);
        expiredOffer = createCredentialOffer(CredentialStatusType.OFFERED, now().minusSeconds(1).getEpochSecond(), offerData);
        valid = createCredentialOffer(CredentialStatusType.OFFERED, now().plusSeconds(1000).getEpochSecond(), offerData);
        suspended = createCredentialOffer(CredentialStatusType.SUSPENDED, now().plusSeconds(1000).getEpochSecond(), offerData);
        issued = createCredentialOffer(CredentialStatusType.ISSUED, now().minusSeconds(1).getEpochSecond(), null);

        when(applicationProperties.getIssuerId()).thenReturn("did:example:123456789");

        when(credentialOfferRepository.findById(expiredOffer.getId())).thenReturn(Optional.of(expiredOffer));
        when(credentialOfferRepository.findById(valid.getId())).thenReturn(Optional.of(valid));
        when(credentialOfferRepository.findById(issued.getId())).thenReturn(Optional.of(issued));
        when(credentialOfferRepository.findById(suspended.getId())).thenReturn(Optional.of(suspended));

        when(credentialOfferRepository.findByIdForUpdate(expiredOffer.getId())).thenReturn(Optional.of(expiredOffer));
        when(credentialOfferRepository.findByIdForUpdate(valid.getId())).thenReturn(Optional.of(valid));
        when(credentialOfferRepository.findByIdForUpdate(issued.getId())).thenReturn(Optional.of(issued));
        when(credentialOfferRepository.findByIdForUpdate(suspended.getId())).thenReturn(Optional.of(suspended));

        when(credentialOfferRepository.save(expiredOffer)).thenReturn(expiredOffer);
        when(credentialOfferRepository.save(valid)).thenReturn(valid);
        when(credentialOfferRepository.save(issued)).thenReturn(issued);
        when(credentialOfferRepository.save(suspended)).thenReturn(suspended);

        credentialService = new CredentialManagementService(
                credentialOfferRepository,
                credentialOfferStatusRepository,
                new ObjectMapper(),
                statusListService,
                issuerMetadata,
                applicationProperties,
                dataIntegrityService,
                applicationEventPublisher
        );

        var statusListUris = List.of("https://example.com/status-list");
        var statusListToken = new TokenStatusListToken(2, 10000);
        statusList = StatusList.builder().type(StatusListType.TOKEN_STATUS_LIST)
                .config(Map.of("bits", 2))
                .uri("https://localhost:8080/status")
                .statusZipped(statusListToken.getStatusListClaims().get("lst").toString())
                .nextFreeIndex(0)
                .maxLength(10000)
                .build();

        createCredentialRequestDto = CreateCredentialRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test-metadata"))
                .credentialSubjectData(offerData)
                .offerValiditySeconds(3600)
                .statusLists(statusListUris)
                .build();
    }

    @Test
    void offerDeeplinkTest() {
        var validDeeplink = credentialService.getCredentialOfferDeeplink(valid.getId());

        // THEN
        assertNotNull(validDeeplink);
        assertTrue(validDeeplink.contains("version"));
        assertTrue(validDeeplink.contains("credential_offer="));
        assertTrue(validDeeplink.contains("grant-type"));
        assertTrue(validDeeplink.contains("pre-authorized_code"));
    }

    @Test
    void getCredentialInvalidateOfferWhenExpired() {

        // note: getting an expired offer will immediately update it to expired
        var expiredOfferId = expiredOffer.getId();
        var response = credentialService.getCredentialOfferInformation(expiredOfferId);

        Mockito.verify(credentialOfferRepository, Mockito.times(1)).findByIdForUpdate(expiredOfferId);
        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(any());

        // offer data should be null after expiration therefore no offer data or deeplink should be returned
        assertNull(response.holderJWKs());
        assertNull(response.clientAgentInfo());

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

        when(applicationProperties.getDeeplinkSchema()).thenReturn("test-swiyu");
        CredentialInfoResponseDto response = credentialService.getCredentialOfferInformation(valid.getId());

        assertNotNull(response);
        assertTrue(response.offerDeeplink().startsWith("test-swiyu://"));

        credentialService.getCredentialOfferDeeplink(valid.getId());
    }

    @Test
    void updateCredentialStatus_shouldUpdateStatusToRevoked() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferStatusId(issued.getId())).thenReturn(offerStatusSet);

        doNothing().when(statusListService).revoke(offerStatusSet);

        var updated = credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.REVOKED);

        assertEquals(CredentialStatusTypeDto.REVOKED, updated.getCredentialStatus());
        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(issued);
        Mockito.verify(applicationEventPublisher).publishEvent(Mockito.any(StateChangeEvent.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CANCELLED", "REVOKED"})
    void updateCredentialStatus_shouldThrowIfStatusIsTerminal(String type) {

        var offer = createCredentialOffer(CredentialStatusType.EXPIRED, now().plusSeconds(1000).getEpochSecond(), offerData);
        var offerId = offer.getId();
        var requestedNewStatus = UpdateCredentialStatusRequestTypeDto.valueOf(type);

        when(credentialOfferRepository.findByIdForUpdate(offer.getId())).thenReturn(Optional.of(offer));

        assertThrows(BadRequestException.class, () ->
                credentialService.updateCredentialStatus(offerId, requestedNewStatus)
        );
    }

    @Test
    void updateCredentialStatus_shouldNotUpdateIfStatusUnchanged() {
        credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.ISSUED);

        Mockito.verify(credentialOfferRepository, Mockito.never()).save(any());
    }

    @Test
    void testHandlePostIssuanceStatusChangeRevoked_thenCallCorrectFunction() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferStatusId(issued.getId())).thenReturn(offerStatusSet);

        doNothing().when(statusListService).revoke(offerStatusSet);

        credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.REVOKED);

        Mockito.verify(statusListService, Mockito.times(1)).revoke(offerStatusSet);
    }

    @Test
    void testHandlePostIssuanceStatusChangeSuspended_thenCallCorrectFunction() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferStatusId(issued.getId())).thenReturn(offerStatusSet);

        doNothing().when(statusListService).revoke(offerStatusSet);

        credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.SUSPENDED);

        Mockito.verify(statusListService, Mockito.times(1)).suspend(offerStatusSet);
    }

    @Test
    void testHandlePostIssuanceStatusChangeIssued_thenCallCorrectFunction() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferStatusId(suspended.getId())).thenReturn(offerStatusSet);

        doNothing().when(statusListService).revoke(offerStatusSet);

        credentialService.updateCredentialStatus(suspended.getId(), UpdateCredentialStatusRequestTypeDto.ISSUED);

        Mockito.verify(statusListService, Mockito.times(1)).revalidate(offerStatusSet);
    }

    @Test
    void testCreateCredentialOffer_notAllStatusListsFound() {

        var statusListUris = List.of("https://example.com/status-list", "https://example.com/another-status-list");

        createCredentialRequestDto = CreateCredentialRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(offerData)
                .offerValiditySeconds(3600)
                .statusLists(statusListUris)
                .build();

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialRequestDto));
        assertTrue(exception.getMessage().contains("Could not resolve all provided status lists, only found https://localhost:8080/status"));
    }

    @Test
    void testCreateCredentialOfferInvalidCredential_thenBadRequest() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("different-test-metadata", mock(CredentialConfiguration.class)));
        when(credentialOfferRepository.save(any())).thenAnswer(new Answer<CredentialOffer>() {
            @Override
            public CredentialOffer answer(InvocationOnMock invocation) {
                return invocation.getArgument(0);
            }
        });

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialRequestDto));

        assertTrue(exception.getMessage().contains("Credential offer metadata test-metadata is not supported - should be one of different-test-metadata"));
    }

    @Test
    void testCreateCredentialOfferWithInvalidSpan_ValidUntilBeforeNow_thenBadRequest() {

        var statusListUris = List.of("https://example.com/status-list");

        createCredentialRequestDto = CreateCredentialRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test-metadata"))
                .credentialSubjectData(offerData)
                .offerValiditySeconds(3600)
                .credentialValidUntil(Instant.now().minusSeconds(1000)) // Invalid span
                .statusLists(statusListUris)
                .build();

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));
        when(credentialOfferRepository.save(any())).thenAnswer(new Answer<CredentialOffer>() {
            @Override
            public CredentialOffer answer(InvocationOnMock invocation) {
                return invocation.getArgument(0);
            }
        });

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialRequestDto));
        assertTrue(exception.getMessage().contains("Credential is already expired (would only be valid until"));
    }

    @Test
    void testCreateCredentialOfferWithInvalidSpan_ValidFromAfterValidUntil_thenBadRequest() {

        var statusListUris = List.of("https://example.com/status-list");

        createCredentialRequestDto = CreateCredentialRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test-metadata"))
                .credentialSubjectData(offerData)
                .offerValiditySeconds(3600)
                .credentialValidUntil(Instant.now().plusSeconds(1000)) // Invalid span
                .credentialValidFrom(Instant.now().plusSeconds(2000)) // Valid from is before valid until
                .statusLists(statusListUris)
                .build();

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));
        when(credentialOfferRepository.save(any())).thenAnswer(new Answer<CredentialOffer>() {
            @Override
            public CredentialOffer answer(InvocationOnMock invocation) {
                return invocation.getArgument(0);
            }
        });

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialRequestDto));
        assertTrue(exception.getMessage().contains("Credential would never be valid"));
    }

    @Test
    void testCreateCredentialOfferWithInvalidSpan_AlreadyExpired_thenBadRequest() {

        var statusListUris = List.of("https://example.com/status-list");

        createCredentialRequestDto = CreateCredentialRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test-metadata"))
                .credentialSubjectData(offerData)
                .offerValiditySeconds(3600)
                .credentialValidUntil(Instant.now()) // Invalid span
                .credentialValidFrom(Instant.now().plusSeconds(1000)) // Valid from is before valid until
                .statusLists(statusListUris)
                .build();

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));
        when(credentialOfferRepository.save(any())).thenAnswer(new Answer<CredentialOffer>() {
            @Override
            public CredentialOffer answer(InvocationOnMock invocation) {
                return invocation.getArgument(0);
            }
        });

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialRequestDto));
        assertTrue(exception.getMessage().contains("Credential is already expired"));
    }

    @Test
    void testCreateCredentialOfferMissingClaim_thenBadRequest() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));

        var credConfig = mock(CredentialConfiguration.class);
        var claim = new CredentialClaim();
        claim.setMandatory(true);
        claim.setValueType("string");

        when(credConfig.getCredentialDefinition()).thenReturn(null);
        when(credConfig.getClaims()).thenReturn(Map.of("claim", claim));
        when(credConfig.getFormat()).thenReturn("vc+sd-jwt");
        when(credConfig.getVct()).thenReturn("test-vct");

        when(credConfig.getCryptographicBindingMethodsSupported()).thenReturn(List.of("did:jwk", "jwk"));
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", credConfig));
        when(issuerMetadata.getCredentialConfigurationById("test-metadata")).thenReturn(credConfig);
        when(credentialOfferRepository.save(any())).thenAnswer(new Answer<CredentialOffer>() {
            @Override
            public CredentialOffer answer(InvocationOnMock invocation) {
                return invocation.getArgument(0);
            }
        });

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialRequestDto));

        assertTrue(exception.getMessage().contains("Credential claims (credential subject data) is missing!"));
    }

    @Test
    void testCreateCredentialOfferAdditionalClaimsData_thenBadRequest() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));

        var credConfig = mock(CredentialConfiguration.class);
        var claim = new CredentialClaim();
        claim.setMandatory(true);
        claim.setValueType("string");

        when(credConfig.getCredentialDefinition()).thenReturn(null);
        when(credConfig.getClaims()).thenReturn(Map.of("hello", claim));
        when(credConfig.getFormat()).thenReturn("vc+sd-jwt");
        when(credConfig.getVct()).thenReturn("test-vct");

        when(credConfig.getCryptographicBindingMethodsSupported()).thenReturn(List.of("did:jwk", "jwk"));
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", credConfig));
        when(issuerMetadata.getCredentialConfigurationById("test-metadata")).thenReturn(credConfig);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(Map.of("hello", "world", "additional", "additionalData"));
        when(credentialOfferRepository.save(any())).thenAnswer(new Answer<CredentialOffer>() {
            @Override
            public CredentialOffer answer(InvocationOnMock invocation) {
                return invocation.getArgument(0);
            }
        });

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialRequestDto));

        assertTrue(exception.getMessage().contains("Unexpected credential claims found!"));
    }

    @Test
    void testCreateCredentialOffer_thenSuccess() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));

        var credConfig = mock(CredentialConfiguration.class);
        var claim = new CredentialClaim();
        claim.setMandatory(true);
        claim.setValueType("string");

        when(credConfig.getCredentialDefinition()).thenReturn(null);
        when(credConfig.getClaims()).thenReturn(Map.of("hello", claim));
        when(credConfig.getFormat()).thenReturn("vc+sd-jwt");
        when(credConfig.getVct()).thenReturn("test-vct");

        when(credConfig.getCryptographicBindingMethodsSupported()).thenReturn(List.of("did:jwk", "jwk"));
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", credConfig));
        when(issuerMetadata.getCredentialConfigurationById("test-metadata")).thenReturn(credConfig);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(offerData);
        when(credentialOfferRepository.save(any())).thenAnswer(new Answer<CredentialOffer>() {
            @Override
            public CredentialOffer answer(InvocationOnMock invocation) {
                return invocation.getArgument(0);
            }
        });

        assertDoesNotThrow(() -> credentialService.createCredentialOfferAndGetDeeplink(createCredentialRequestDto));
    }

    @Test
    void updateOfferDataForDeferred_shouldUpdateOfferData_whenDeferredAndInDeferredState() {
        // Arrange
        UUID credentialId = UUID.randomUUID();
        CredentialOffer credentialOffer = mock(CredentialOffer.class);

        when(credentialOffer.isDeferredOffer()).thenReturn(true);
        when(credentialOffer.getCredentialStatus()).thenReturn(CredentialStatusType.DEFERRED);
        when(credentialOfferRepository.findByIdForUpdate(credentialId)).thenReturn(Optional.of(credentialOffer));
        doNothing().when(credentialOffer).markAsReadyForIssuance(any());
        when(credentialOfferRepository.save(credentialOffer)).thenReturn(credentialOffer);

        UpdateStatusResponseDto response = credentialService.updateOfferDataForDeferred(credentialId, offerData);

        verify(credentialOfferRepository).findByIdForUpdate(credentialId);
        verify(credentialOffer).markAsReadyForIssuance(any());
        verify(credentialOfferRepository).save(credentialOffer);
        assertNotNull(response);
    }

    @Test
    void updateOfferDataForDeferred_shouldThrow_whenNotDeferredOrNotInDeferredState() {
        // Arrange
        UUID credentialId = UUID.randomUUID();
        Map<String, Object> offerDataMap = Map.of("claim", "value");
        CredentialOffer credentialOffer = mock(CredentialOffer.class);

        when(credentialOffer.isDeferredOffer()).thenReturn(false);
        when(credentialOffer.getCredentialStatus()).thenReturn(CredentialStatusType.DEFERRED);
        when(credentialOfferRepository.findByIdForUpdate(credentialId)).thenReturn(Optional.of(credentialOffer));

        // Act & Assert
        assertThrows(BadRequestException.class, () -> credentialService.updateOfferDataForDeferred(credentialId, offerDataMap));
    }

    @Test
    void updateOfferDataForDeferred_shouldUpdateCredentialOfferData() {
        // Arrange
        UUID credentialId = UUID.randomUUID();
        Map<String, Object> offerDataMap = Map.of("claim", "value");
        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialStatusType.DEFERRED,
                Instant.now().plusSeconds(600).getEpochSecond(),
                Map.of(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                null);

        when(credentialOfferRepository.findByIdForUpdate(credentialId)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.save(credentialOffer)).thenReturn(credentialOffer);

        credentialService.updateOfferDataForDeferred(credentialId, offerDataMap);

        verify(credentialOfferRepository, times(1)).save(credentialOffer);
    }

    private @NotNull Set<CredentialOfferStatus> getCredentialOfferStatusSet() {
        return Set.of(getCredentialOfferStatus(issued.getId(), UUID.randomUUID()));
    }

    private CredentialOfferStatus getCredentialOfferStatus(UUID offerId, UUID statusId) {
        return CredentialOfferStatus.builder()
                .id(new CredentialOfferStatusKey(offerId, statusId))
                .index(1)
                .build();
    }

    private CredentialOffer createCredentialOffer(CredentialStatusType statusType, long offerExpirationTimestamp, Map<String, Object> offerData) {

        return getCredentialOffer(statusType, offerExpirationTimestamp, offerData, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), null, null);
    }
}