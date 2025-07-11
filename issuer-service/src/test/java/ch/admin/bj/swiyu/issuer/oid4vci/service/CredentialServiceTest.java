/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialClaim;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.service.*;
import com.fasterxml.jackson.core.JsonProcessingException;
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

import java.time.Instant;
import java.util.*;

import static java.time.Instant.now;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialServiceTest {
    private final Map<String, Object> offerData = Map.of("hello", "world");
    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock
    CredentialOfferRepository credentialOfferRepository;
    CredentialService credentialService;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    private StatusListService statusListService;
    private ApplicationProperties applicationProperties;
    private IssuerMetadataTechnical issuerMetadata;
    private DataIntegrityService dataIntegrityService;
    private WebhookService webhookService;
    private CredentialOffer expiredOffer;
    private CredentialOffer valid;
    private CredentialOffer issued;
    private CredentialOffer suspended;
    private StatusList statusList;
    private CreateCredentialRequestDto createCredentialRequestDto;
    private CredentialFormatFactory credentialFormatFactory;

    @BeforeEach
    void setUp() {
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        statusListService = Mockito.mock(StatusListService.class);
        KeyAttestationService keyAttestationService = Mockito.mock(KeyAttestationService.class);
        issuerMetadata = Mockito.mock(IssuerMetadataTechnical.class);
        credentialFormatFactory = Mockito.mock(CredentialFormatFactory.class);
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        OpenIdIssuerConfiguration openIdIssuerConfiguration = Mockito.mock(OpenIdIssuerConfiguration.class);
        dataIntegrityService = Mockito.mock(DataIntegrityService.class);
        webhookService = Mockito.mock(WebhookService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);

        expiredOffer = getCredentialOffer(CredentialStatusType.OFFERED, now().minusSeconds(1).getEpochSecond(), offerData);
        valid = getCredentialOffer(CredentialStatusType.OFFERED, now().plusSeconds(1000).getEpochSecond(), offerData);
        suspended = getCredentialOffer(CredentialStatusType.SUSPENDED, now().plusSeconds(1000).getEpochSecond(), offerData);
        issued = getCredentialOffer(CredentialStatusType.ISSUED, now().minusSeconds(1).getEpochSecond(), null);

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
        var response = credentialService.getCredentialOfferInformation(expiredOfferId);

        Mockito.verify(credentialOfferRepository, Mockito.times(1)).findByIdForUpdate(expiredOfferId);
        Mockito.verify(credentialOfferRepository, Mockito.times(1)).save(any());

        // offer data should be null after expiration therefore no offer data or deeplink should be returned
        assertNull(response.holderJWK());
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
        Mockito.verify(webhookService, Mockito.times(1)).produceStateChangeEvent(issued.getId(), CredentialStatusType.REVOKED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CANCELLED", "REVOKED"})
    void updateCredentialStatus_shouldThrowIfStatusIsTerminal(String type) {

        var offer = getCredentialOffer(CredentialStatusType.EXPIRED, now().plusSeconds(1000).getEpochSecond(), offerData);
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
    void givenExpiredToken_whenGetCredential_thenThrowOAuthException() throws OAuthException {
        // Given
        var uuid = UUID.randomUUID();

        var expirationTimeStamp = now().plusSeconds(1000).getEpochSecond();
        var offer = getCredentialOffer(CredentialStatusType.IN_PROGRESS, expirationTimeStamp, offerData, uuid, uuid, UUID.randomUUID(), Map.of(), null);
        offer.setTokenExpirationTimestamp(Instant.now().minusSeconds(600).getEpochSecond());

        when(credentialOfferRepository.findByAccessToken(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var credentialRequestDto = getCredentialRequestDto();
        var accessToken = uuid.toString();
        var ex = assertThrows(OAuthException.class, () -> credentialService.createCredential(credentialRequestDto, accessToken, null));

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
        var offer = getCredentialOffer(CredentialStatusType.OFFERED, expirationTimeStamp, offerData, uuid, preAuthorizedCode, UUID.randomUUID(), Map.of(), null);

        when(credentialOfferRepository.findByAccessToken(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var credentialRequestDto = getCredentialRequestDto();
        var uuidString = uuid.toString();
        var ex = assertThrows(OAuthException.class, () ->
                credentialService.createCredential(credentialRequestDto, uuidString, null));

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
        var offer = getCredentialOffer(CredentialStatusType.OFFERED, expirationTimeStamp, offerData, uuid, uuid, UUID.randomUUID(), Map.of(), null);

        when(credentialOfferRepository.findByPreAuthorizedCode(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var uuidString = uuid.toString();
        var ex = assertThrows(OAuthException.class,
                () -> credentialService.issueOAuthToken(uuidString));

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
                credentialService.createCredential(createCredentialRequestDto));
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
                credentialService.createCredential(createCredentialRequestDto));

        assertTrue(exception.getMessage().contains("Credential offer metadata test-metadata is not supported - should be one of different-test-metadata"));
    }

    @Test
    void testCreateCredentialOffer_invalidFormat_thenBadRequest() {

        var credentialRequestDto = getCredentialRequestDto();
        var clientInfo = getClientInfo();
        var claim = new CredentialClaim();
        claim.setMandatory(true);
        claim.setValueType("string");
        var credConfig = mock(CredentialConfiguration.class);
        when(credConfig.getCredentialDefinition()).thenReturn(null);
        when(credConfig.getClaims()).thenReturn(Map.of("hello", claim));
        when(credConfig.getFormat()).thenReturn("not-vc+sd-jwt");
        when(credConfig.getVct()).thenReturn("test-vct");

        var credentialOffer = getCredentialOffer(
                CredentialStatusType.IN_PROGRESS,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                Map.of("deferred", false),
                null);

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("different-test-metadata", mock(CredentialConfiguration.class)));
        when(credentialOfferRepository.findByAccessToken(credentialOffer.getAccessToken())).thenReturn(Optional.of(credentialOffer));
        when(issuerMetadata.getCredentialConfigurationById("test")).thenReturn(credConfig);

        var accessToken = credentialOffer.getAccessToken().toString();
        var exception = assertThrows(Oid4vcException.class, () ->
                credentialService.createCredential(credentialRequestDto, accessToken, clientInfo));

        assertTrue(exception.getMessage().contains("Mismatch between requested and offered format."));
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
                credentialService.createCredential(createCredentialRequestDto));
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
                credentialService.createCredential(createCredentialRequestDto));
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
                credentialService.createCredential(createCredentialRequestDto));
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
                credentialService.createCredential(createCredentialRequestDto));

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
                credentialService.createCredential(createCredentialRequestDto));

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

        assertDoesNotThrow(() -> credentialService.createCredential(createCredentialRequestDto));
    }

    @Test
    void testCreateCredential_deferred() throws JsonProcessingException {

        var credentialRequestDto = getCredentialRequestDto();
        var clientInfo = getClientInfo();

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialStatusType.IN_PROGRESS,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                Map.of("deferred", true),
                null);

        when(credentialOfferRepository.findByAccessToken(credentialOffer.getAccessToken())).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Mock the factory to return the builder
        var sdJwtCredential = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder(anyString())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialOffer(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialResponseEncryption(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.holderBinding(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialType(any())).thenReturn(sdJwtCredential);
        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));

        var claim = new CredentialClaim();
        claim.setMandatory(true);
        claim.setValueType("string");
        var credConfig = mock(CredentialConfiguration.class);
        when(credConfig.getCredentialDefinition()).thenReturn(null);
        when(credConfig.getClaims()).thenReturn(Map.of("hello", claim));
        when(credConfig.getFormat()).thenReturn("vc+sd-jwt");
        when(credConfig.getVct()).thenReturn("test-vct");

        when(credConfig.getCryptographicBindingMethodsSupported()).thenReturn(List.of("did:jwk", "jwk"));
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test", credConfig));
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(credConfig);

        credentialService.createCredential(credentialRequestDto, credentialOffer.getAccessToken().toString(), clientInfo);

        // check if is issued && data removed
        assertEquals(CredentialStatusType.DEFERRED, credentialOffer.getCredentialStatus());
        String clientInfoString = objectMapper.writeValueAsString(clientInfo);
        verify(webhookService).produceDeferredEvent(credentialOffer.getId(), clientInfoString);
    }

    @Test
    void updateOfferDataForDeferred_shouldUpdateOfferData_whenDeferredAndInDeferredState() {
        // Arrange
        UUID credentialId = UUID.randomUUID();
        CredentialOffer credentialOffer = mock(CredentialOffer.class);

        when(credentialOffer.isDeferred()).thenReturn(true);
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

        when(credentialOffer.isDeferred()).thenReturn(false);
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
                Map.of("deferred", true),
                null);

        when(credentialOfferRepository.findByIdForUpdate(credentialId)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.save(credentialOffer)).thenReturn(credentialOffer);

        credentialService.updateOfferDataForDeferred(credentialId, offerDataMap);

        verify(credentialOfferRepository, times(1)).save(credentialOffer);
    }

    @Test
    void testCreateCredentialFromDeferredRequest_notReady_thenException() {

        UUID accessToken = UUID.randomUUID();

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialStatusType.DEFERRED,
                Instant.now().plusSeconds(600).getEpochSecond(),
                Map.of(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                Map.of("deferred", true),
                UUID.randomUUID());

        DeferredCredentialRequestDto deferredRequest = new DeferredCredentialRequestDto(credentialOffer.getTransactionId(), new HashMap<>());

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Act
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(Oid4vcException.class, () ->
                credentialService.createCredentialFromDeferredRequest(deferredRequest, accessTokenString));

        assertEquals("The credential is not marked as ready to be issued", exception.getMessage());
    }

    @Test
    void testCreateCredentialFromDeferredRequest_accesTokenExpired_thenException() {

        UUID transactionId = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        DeferredCredentialRequestDto deferredRequest = new DeferredCredentialRequestDto(transactionId, new HashMap<>());

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialStatusType.DEFERRED,
                Instant.now().minusSeconds(600).getEpochSecond(),
                Map.of(),
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                Map.of("deferred", true),
                transactionId);

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));

        // Act
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(OAuthException.class, () ->
                credentialService.createCredentialFromDeferredRequest(deferredRequest, accessTokenString));

        assertEquals("Invalid accessToken", exception.getMessage());
    }

    @Test
    void testCreateCredentialFromDeferredRequest_success() {

        UUID transactionId = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        DeferredCredentialRequestDto deferredRequest = new DeferredCredentialRequestDto(transactionId, new HashMap<>());

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialStatusType.READY,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                Map.of("deferred", true),
                transactionId);

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Mock the factory to return the builder
        var sdJwtCredential = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder(anyString())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialOffer(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialResponseEncryption(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.holderBinding(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialType(any())).thenReturn(sdJwtCredential);

        // Act
        credentialService.createCredentialFromDeferredRequest(deferredRequest, accessToken.toString());

        // check if is issued && data removed
        assertEquals(CredentialStatusType.ISSUED, credentialOffer.getCredentialStatus());
        assertNull(credentialOffer.getOfferData());
        assertNull(credentialOffer.getTransactionId());
        assertNull(credentialOffer.getHolderJWK());
        assertNull(credentialOffer.getClientAgentInfo());

        verify(credentialOfferRepository).save(credentialOffer);
        verify(webhookService).produceStateChangeEvent(any(), any());
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

    private CredentialOffer getCredentialOffer(CredentialStatusType statusType, long offerExpirationTimestamp, Map<String, Object> offerData) {

        return getCredentialOffer(statusType, offerExpirationTimestamp, offerData, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Map.of(), null);
    }

    private CredentialOffer getCredentialOffer(CredentialStatusType status, long offerExpirationTimestamp, Map<String, Object> offerData, UUID accessToken, UUID preAuthorizedCode, UUID nonce, Map<String, Object> offerMetadata, UUID transactionId) {

        return new CredentialOffer(
                UUID.randomUUID(),
                status,
                List.of("test"),
                offerData,
                offerMetadata,
                accessToken,
                transactionId,
                null,
                null,
                Instant.now().plusSeconds(600).getEpochSecond(),
                nonce,
                preAuthorizedCode,
                offerExpirationTimestamp,
                Instant.now(),
                Instant.now(),
                new CredentialRequestClass("vc+sd-jwt", null, null)
        );
    }

    private @NotNull CredentialRequestDto getCredentialRequestDto() {
        return new CredentialRequestDto(
                "vc+sd-jwt",
                new HashMap<>(),
                null
        );
    }

    private @NotNull ClientAgentInfo getClientInfo() {
        return new ClientAgentInfo("test-agent", "1.0", "test-client", "test-client-id");
    }
}