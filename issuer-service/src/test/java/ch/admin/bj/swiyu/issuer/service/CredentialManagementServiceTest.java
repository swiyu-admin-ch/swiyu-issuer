/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialClaim;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.webhook.StateChangeEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonParser;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.context.ApplicationEventPublisher;

import java.net.URLDecoder;
import java.time.Instant;
import java.util.*;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils.getCredentialOffer;
import static java.time.Instant.now;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialManagementServiceTest {
    public static final String TEST_STATUS_LIST_URI = "https://localhost:8080/status";
    private final Map<String, Object> offerData = Map.of("hello", "world");
    @Mock
    CredentialOfferRepository credentialOfferRepository;
    CredentialManagementService credentialService;
    @Mock
    ApplicationEventPublisher applicationEventPublisher;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    private CredentialManagementRepository credentialManagementRepository;
    private StatusListService statusListService;
    private ApplicationProperties applicationProperties;
    private IssuerMetadata issuerMetadata;
    private DataIntegrityService dataIntegrityService;
    private CredentialOffer expiredOffer;
    private CredentialOffer valid;
    private CredentialOffer issued;
    private CredentialOffer suspended;
    private StatusList statusList;
    private CreateCredentialOfferRequestDto createCredentialOfferRequestDto;
    private AvailableStatusListIndexRepository availableStatusListIndexRepository;
    private CredentialManagement mgmt;

    @BeforeEach
    void setUp() {
        availableStatusListIndexRepository = Mockito.mock(AvailableStatusListIndexRepository.class);
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        credentialManagementRepository = Mockito.mock(CredentialManagementRepository.class);
        statusListService = Mockito.mock(StatusListService.class);
        issuerMetadata = Mockito.mock(IssuerMetadata.class);
        var mockCredentialMetadata = Mockito.mock(CredentialConfiguration.class);
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

        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test", mockCredentialMetadata));
        when(issuerMetadata.getCredentialConfigurationById("test")).thenReturn(mockCredentialMetadata);
        when(mockCredentialMetadata.getFormat()).thenReturn("dc+sd-jwt");
        when(mockCredentialMetadata.getClaims()).thenReturn(Map.of("hello", Mockito.mock(CredentialClaim.class)));
        when(dataIntegrityService.getVerifiedOfferData(Mockito.any(), Mockito.any())).thenReturn(offerData);

        credentialService = new CredentialManagementService(
                credentialOfferRepository,
                credentialManagementRepository,
                credentialOfferStatusRepository,

                new ObjectMapper(),
                statusListService,
                issuerMetadata,
                applicationProperties,
                dataIntegrityService,
                applicationEventPublisher,
                availableStatusListIndexRepository
        );

        var statusListUris = List.of("https://example.com/status-list");
        var statusListToken = new TokenStatusListToken(2, 10000);
        statusList = StatusList.builder().type(StatusListType.TOKEN_STATUS_LIST)
                .config(Map.of("bits", 2))
                .uri(TEST_STATUS_LIST_URI)
                .statusZipped(statusListToken.getStatusListClaims().get("lst").toString())
                .maxLength(10000)
                .build();
        when(availableStatusListIndexRepository.findById(TEST_STATUS_LIST_URI)).thenReturn(
                Optional.of(AvailableStatusListIndexes.builder()
                        .statusListUri(TEST_STATUS_LIST_URI)
                        .freeIndexes(IntStream.range(0, 10).boxed().toList())
                        .build()));

        createCredentialOfferRequestDto = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test-metadata"))
                .credentialSubjectData(offerData)
                .offerValiditySeconds(3600)
                .statusLists(statusListUris)
                .build();

        mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialOffers(Set.of(valid))
                .build();
    }

    @Test
    void getCredentialInvalidateOfferWhenExpired() {

        var mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialOffers(Set.of(expiredOffer))
                .build();

        when(credentialManagementRepository.findById(mgmt.getId())).thenReturn(Optional.of(mgmt));
        when(credentialManagementRepository.save(any())).thenReturn(mgmt);

        // note: getting an expired offer will immediately update it to expired
        var expiredOfferId = expiredOffer.getId();
        var response = credentialService.getCredentialOfferInformation(mgmt.getId());

        Mockito.verify(credentialOfferRepository, Mockito.times(1)).findByIdForUpdate(expiredOfferId);
        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(any());

        // offer data should be null after expiration therefore no offer data or deeplink should be returned
        assertNull(response.credentialOffers().getFirst().holderJWKs());
        assertNull(response.credentialOffers().getFirst().clientAgentInfo());

        var statusResponse = credentialService.getCredentialStatus(mgmt.getId());

        assertEquals(CredentialStatusTypeDto.EXPIRED, statusResponse.getStatus());
    }

    @Test
    void updateCredentialStatus_shouldUpdateStatusToRevoked() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialManagementRepository.findById(issued.getCredentialManagement().getId())).thenReturn(Optional.of(issued.getCredentialManagement()));
        when(credentialManagementRepository.save(issued.getCredentialManagement())).thenReturn(issued.getCredentialManagement());
        when(credentialOfferStatusRepository.findByOfferId(issued.getId())).thenReturn(offerStatusSet);

        when(statusListService.revoke(offerStatusSet)).thenReturn(List.of(UUID.randomUUID()));

        var updated = credentialService.updateCredentialStatus(issued.getCredentialManagement().getId(), UpdateCredentialStatusRequestTypeDto.REVOKED);

        assertEquals(CredentialStatusTypeDto.REVOKED, updated.getCredentialStatus());
        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(issued);
        Mockito.verify(applicationEventPublisher).publishEvent(Mockito.any(StateChangeEvent.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CANCELLED", "REVOKED"})
    void updateCredentialStatus_shouldThrowIfStatusIsTerminal(String type) {

        var offer = createCredentialOffer(CredentialStatusType.EXPIRED, now().plusSeconds(1000).getEpochSecond(), offerData);
        var requestedNewStatus = UpdateCredentialStatusRequestTypeDto.valueOf(type);

        when(credentialOfferRepository.findByIdForUpdate(offer.getId())).thenReturn(Optional.of(offer));
        when(credentialManagementRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(credentialManagementRepository.findById(offer.getCredentialManagement().getId())).thenReturn(Optional.ofNullable(offer.getCredentialManagement()));

        assertThrows(BadRequestException.class, () ->
                credentialService.updateCredentialStatus(offer.getCredentialManagement().getId(), requestedNewStatus)
        );
    }

    @Test
    void updateCredentialStatus_shouldNotUpdateIfStatusUnchanged() {
        var mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialOffers(Set.of(issued))
                .build();

        Mockito.when(credentialManagementRepository.findById(any())).thenReturn(Optional.of(mgmt));
        Mockito.when(credentialManagementRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        credentialService.updateCredentialStatus(issued.getId(), UpdateCredentialStatusRequestTypeDto.ISSUED);

        Mockito.verify(credentialOfferRepository, Mockito.never()).save(any());
    }

    @Test
    void testHandlePostIssuanceStatusChangeRevoked_thenCallCorrectFunction() {

        var mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialOffers(Set.of(issued))
                .build();

        issued.setCredentialManagement(mgmt);

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferId(issued.getId())).thenReturn(offerStatusSet);

        when(statusListService.revoke(offerStatusSet)).thenReturn(List.of(UUID.randomUUID()));

        when(credentialManagementRepository.findById(any())).thenReturn(Optional.of(mgmt));
        when(credentialManagementRepository.save(any())).thenReturn(mgmt);

        credentialService.updateCredentialStatus(mgmt.getId(), UpdateCredentialStatusRequestTypeDto.REVOKED);

        Mockito.verify(statusListService, Mockito.times(1)).revoke(offerStatusSet);
    }

    @Test
    void testHandlePostIssuanceStatusChangeSuspended_thenCallCorrectFunction() {

        when(credentialManagementRepository.findById(issued.getCredentialManagement().getId())).thenReturn(Optional.of(issued.getCredentialManagement()));
        when(credentialManagementRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferId(issued.getId())).thenReturn(offerStatusSet);

        when(statusListService.revoke(offerStatusSet)).thenReturn(List.of(UUID.randomUUID()));

        credentialService.updateCredentialStatus(issued.getCredentialManagement().getId(), UpdateCredentialStatusRequestTypeDto.SUSPENDED);

        Mockito.verify(statusListService, Mockito.times(1)).suspend(offerStatusSet);
    }

    @Test
    void testHandlePostIssuanceStatusChangeIssued_thenCallCorrectFunction() {

        Set<CredentialOfferStatus> offerStatusSet = getCredentialOfferStatusSet();

        when(credentialOfferStatusRepository.findByOfferId(suspended.getId())).thenReturn(offerStatusSet);
        when(credentialManagementRepository.save(any())).thenAnswer(i -> i.getArgument(0));
        when(credentialManagementRepository.findById(suspended.getCredentialManagement().getId())).thenReturn(Optional.of(suspended.getCredentialManagement()));

        when(statusListService.revoke(offerStatusSet)).thenReturn(List.of(UUID.randomUUID()));

        credentialService.updateCredentialStatus(suspended.getCredentialManagement().getId(), UpdateCredentialStatusRequestTypeDto.ISSUED);

        Mockito.verify(statusListService, Mockito.times(1)).revalidate(offerStatusSet);
    }

    @Test
    void testCreateCredentialOffer_notAllStatusListsFound() {

        var statusListUris = List.of("https://example.com/status-list", "https://example.com/another-status-list");

        createCredentialOfferRequestDto = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(offerData)
                .offerValiditySeconds(3600)
                .statusLists(statusListUris)
                .build();

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto));
        assertTrue(exception.getMessage().contains("Could not resolve all provided status lists, only found https://localhost:8080/status"));
    }

    @Test
    void testCreateCredentialOfferWithInvalidSpan_ValidUntilBeforeNow_thenBadRequest() {

        var statusListUris = List.of("https://example.com/status-list");

        createCredentialOfferRequestDto = CreateCredentialOfferRequestDto.builder()
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
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto));
        assertTrue(exception.getMessage().contains("Credential is already expired (would only be valid until"));
    }

    @Test
    void testCreateCredentialOfferWithInvalidSpan_ValidFromAfterValidUntil_thenBadRequest() {

        var statusListUris = List.of("https://example.com/status-list");

        createCredentialOfferRequestDto = CreateCredentialOfferRequestDto.builder()
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
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto));
        assertTrue(exception.getMessage().contains("Credential would never be valid"));
    }

    @Test
    void testCreateCredentialOfferWithInvalidSpan_AlreadyExpired_thenBadRequest() {

        var statusListUris = List.of("https://example.com/status-list");

        createCredentialOfferRequestDto = CreateCredentialOfferRequestDto.builder()
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
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto));
        assertTrue(exception.getMessage().contains("Credential is already expired"));
    }

    @Test
    void testCreateCredentialOfferMissingClaim_thenBadRequest() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));
        when(dataIntegrityService.getVerifiedOfferData(Mockito.any(), Mockito.any())).thenReturn(new HashMap<>());
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
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto));

        assertThat(exception.getMessage()).contains("Mandatory credential claims are missing! claim");
    }

    @Test
    void testCreateCredentialOfferNoData_thenBadRequest() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));
        when(dataIntegrityService.getVerifiedOfferData(Mockito.any(), Mockito.any())).thenReturn(new HashMap<>());
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

        var offer = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test-metadata"))
                .offerValiditySeconds(3600)
                .statusLists(List.of("https://example.com/status-list"))
                .build();

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(offer));

        assertThat(exception.getMessage()).contains("Unsupported OfferData null");
    }

    @Test
    void testCreateCredentialOfferNullOfferData_thenBadRequest() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));
        when(dataIntegrityService.getVerifiedOfferData(Mockito.any(), Mockito.any())).thenReturn(new HashMap<>());
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

        var offer = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test-metadata"))
                .credentialSubjectData(null)
                .offerValiditySeconds(3600)
                .statusLists(List.of("https://example.com/status-list"))
                .build();

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(offer));

        assertThat(exception.getMessage()).contains("Unsupported OfferData null");
    }

    @Test
    void testCreateCredentialOfferEmptyData_thenBadRequest() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));
        when(dataIntegrityService.getVerifiedOfferData(Mockito.any(), Mockito.any())).thenReturn(new HashMap<>());
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

        var offer = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test-metadata"))
                .credentialSubjectData(Map.of())
                .offerValiditySeconds(3600)
                .statusLists(List.of("https://example.com/status-list"))
                .build();

        var exception = assertThrows(BadRequestException.class, () ->
                credentialService.createCredentialOfferAndGetDeeplink(offer));

        assertThat(exception.getMessage()).contains("Mandatory credential claims are missing! claim");
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
                credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto));

        assertTrue(exception.getMessage().contains("Unexpected credential claims found!"));
    }

    @Test
    void testCreateCredentialOffer_thenSuccess() {

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", mock(CredentialConfiguration.class)));
        when(credentialManagementRepository.save(any())).thenAnswer(i -> i.getArguments()[0]);

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

        assertDoesNotThrow(() -> credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto));
    }

    @Test
    void updateOfferDataForDeferred_shouldUpdateOfferData_whenDeferredAndInDeferredState() {
        // Arrange
        UUID mgmtId = UUID.randomUUID();
        CredentialOfferMetadata credentialMetadata = mock(CredentialOfferMetadata.class);

        CredentialOffer credentialOffer = Mockito.mock(CredentialOffer.class);
        when(credentialOffer.getCredentialMetadata()).thenReturn(new CredentialOfferMetadata(true, null, null, null));
        when(credentialOffer.isDeferredOffer()).thenReturn(true);
        when(credentialOffer.getCredentialStatus()).thenReturn(CredentialStatusType.DEFERRED);
        when(credentialOffer.getOfferExpirationTimestamp()).thenReturn(Instant.now().plusSeconds(600).getEpochSecond());
        when(credentialOffer.getOfferData()).thenReturn(Map.of());
        when(credentialOffer.getMetadataCredentialSupportedId()).thenReturn(List.of("test"));

        var mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialOffers(Set.of(credentialOffer))
                .build();

        when(credentialManagementRepository.findById(any())).thenReturn(Optional.of(mgmt));
        when(credentialManagementRepository.save(any())).thenReturn(mgmt);
        when(credentialMetadata.deferred()).thenReturn(true);

        UpdateStatusResponseDto response = credentialService.updateOfferDataForDeferred(mgmtId, offerData);

        verify(credentialManagementRepository).findById(mgmtId);
        verify(credentialManagementRepository).save(mgmt);
        verify(credentialOffer).markAsReadyForIssuance(any());
        verify(credentialOfferRepository).save(credentialOffer);
        assertNotNull(response);
    }

    @Test
    void updateOfferDataForDeferred_shouldThrow_whenNotDeferredOrNotInDeferredState() {
        // Arrange
        UUID credentialId = UUID.randomUUID();
        UUID mgmtId = UUID.randomUUID();
        Map<String, Object> offerDataMap = Map.of("claim", "value");
        CredentialOffer credentialOffer = mock(CredentialOffer.class);
        CredentialManagement mgmt = mock(CredentialManagement.class);
        when(mgmt.getId()).thenReturn(mgmtId);
        when(mgmt.getCredentialOffers()).thenReturn(Set.of(credentialOffer));
        when(credentialManagementRepository.findById(mgmtId)).thenReturn(Optional.of(mgmt));
        when(credentialManagementRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        when(credentialOffer.isDeferredOffer()).thenReturn(false);
        when(credentialOffer.getCredentialStatus()).thenReturn(CredentialStatusType.DEFERRED);
        when(credentialOfferRepository.findByIdForUpdate(credentialId)).thenReturn(Optional.of(credentialOffer));

        // Act & Assert
        assertThrows(BadRequestException.class, () -> credentialService.updateOfferDataForDeferred(mgmtId, offerDataMap));
    }

    @Test
    void updateOfferDataForDeferred_shouldUpdateCredentialOfferData() {
        // Arrange
        UUID credentialId = UUID.randomUUID();
        Map<String, Object> offerDataMap = Map.of("hello", "world");

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialStatusType.DEFERRED,
                Instant.now().plusSeconds(600).getEpochSecond(),
                Map.of(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                null);

        var mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialOffers(Set.of(credentialOffer))
                .build();

        credentialOffer.setCredentialManagement(mgmt);

        when(credentialManagementRepository.findById(any())).thenReturn(Optional.of(mgmt));
        when(credentialManagementRepository.save(any())).thenReturn(mgmt);

        when(credentialOfferRepository.findByIdForUpdate(credentialId)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.save(credentialOffer)).thenReturn(credentialOffer);

        credentialService.updateOfferDataForDeferred(credentialId, offerDataMap);

        verify(credentialOfferRepository, times(1)).save(credentialOffer);
    }

    @Test
    void getConfigurationOverrideByTenantId_throwsWhenNotFound() {
        var tenantId = UUID.randomUUID();

        var service = new CredentialManagementService(
                credentialOfferRepository,
                credentialManagementRepository,
                (ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository) credentialOfferStatusRepository,
                new ObjectMapper(),
                statusListService,
                issuerMetadata,
                applicationProperties,
                dataIntegrityService,
                applicationEventPublisher,
                availableStatusListIndexRepository
        );

        when(credentialOfferRepository.findByMetadataTenantId(tenantId)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> service.getConfigurationOverrideByTenantId(tenantId));
    }

    @Test
    void testCheckIfCorrectDeeplinkWithTenant_thenSuccess() {

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
        when(credentialOfferRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(credentialManagementRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(applicationProperties.isSignedMetadataEnabled()).thenReturn(true);

        UUID expected = UUID.fromString("4d139b3e-9500-48d3-b603-f7fb1d3a2a58");

        try (MockedStatic<UUID> uuid = Mockito.mockStatic(UUID.class)) {
            uuid.when(UUID::randomUUID).thenReturn(expected);
            var response = credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto);
            assertTrue(response.getOfferDeeplink().contains(expected.toString()));
        }
    }

    @Test
    void testCheckIfCorrectDeeplinkWithDisabledSignedMetadata_thenSuccess() {

        var expectedMetadata = "https://metaddata-test";
        var credentialConfigurationSupportedId = "test-metadata";

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(credentialConfigurationSupportedId, mock(CredentialConfiguration.class)));

        var credConfig = mock(CredentialConfiguration.class);
        var claim = new CredentialClaim();
        claim.setMandatory(true);
        claim.setValueType("string");

        when(credConfig.getCredentialDefinition()).thenReturn(null);
        when(credConfig.getClaims()).thenReturn(Map.of("hello", claim));
        when(credConfig.getFormat()).thenReturn("vc+sd-jwt");
        when(credConfig.getVct()).thenReturn("test-vct");

        when(credConfig.getCryptographicBindingMethodsSupported()).thenReturn(List.of("did:jwk", "jwk"));
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(credentialConfigurationSupportedId, credConfig));
        when(issuerMetadata.getCredentialConfigurationById(credentialConfigurationSupportedId)).thenReturn(credConfig);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(offerData);
        when(credentialOfferRepository.save(any())).thenAnswer(i -> i.getArguments()[0]);
        when(credentialManagementRepository.save(any())).thenAnswer(i -> i.getArguments()[0]);
       //  when(credentialManagementRepository.findById(any())).thenAnswer(i -> i.getArguments()[0]);
        when(applicationProperties.isSignedMetadataEnabled()).thenReturn(false);
        when(applicationProperties.getDeeplinkSchema()).thenReturn("test");
        when(applicationProperties.getExternalUrl()).thenReturn(expectedMetadata);

        var response = credentialService.createCredentialOfferAndGetDeeplink(createCredentialOfferRequestDto);

        var deeplink = response.getOfferDeeplink();

        var decoded = URLDecoder.decode(deeplink, java.nio.charset.StandardCharsets.UTF_8);
        var decodedJsonPart = decoded.split("credential_offer=")[1];
        var deeplinkCredentialOffer = JsonParser.parseString(decodedJsonPart).getAsJsonObject();
        assertEquals(expectedMetadata, deeplinkCredentialOffer.get("credential_issuer").getAsString());
        assertEquals(credentialConfigurationSupportedId, deeplinkCredentialOffer.get("credential_configuration_ids").getAsJsonArray().get(0).getAsString());
    }

    private @NotNull Set<CredentialOfferStatus> getCredentialOfferStatusSet() {
        return Set.of(getCredentialOfferStatus(issued.getId(), UUID.randomUUID()));
    }

    private CredentialOfferStatus getCredentialOfferStatus(UUID offerId, UUID statusId) {
        return CredentialOfferStatus.builder()
                .id(new CredentialOfferStatusKey(offerId, statusId, 1))
                .build();
    }

    private CredentialOffer createCredentialOffer(CredentialStatusType statusType, long offerExpirationTimestamp, Map<String, Object> offerData) {
        var mgmtId = UUID.randomUUID();
        var mgmt = CredentialManagement.builder()
                .id(mgmtId)
                .preAuthorizedCode(UUID.randomUUID())
                .build();

        var offer = getCredentialOffer(statusType, offerExpirationTimestamp, offerData, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), null, null);
        offer.setCredentialManagement(mgmt);

        mgmt.setCredentialOffers(Set.of(offer));
        return offer;
    }
}