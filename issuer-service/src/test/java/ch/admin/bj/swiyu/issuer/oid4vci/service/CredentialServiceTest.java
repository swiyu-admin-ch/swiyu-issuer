/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialClaim;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
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
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.time.Instant;
import java.util.*;

import static java.time.Instant.now;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CredentialServiceTest {
    private final Map<String, Object> offerData = Map.of("hello", "world");
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

    private static CredentialOffer getCredentialOffer(CredentialStatusType status, HashMap<String, Object> offerData, UUID accessToken, UUID preAuthorizedCode, UUID nonce) {

        return new CredentialOffer(
                UUID.randomUUID(),
                status,
                Collections.emptyList(),
                offerData,
                new HashMap<>(),
                accessToken,
                null,
                null,
                null,
                Instant.now().plusSeconds(600).getEpochSecond(),
                nonce,
                preAuthorizedCode,
                Instant.now().plusSeconds(600).getEpochSecond(),
                Instant.now(),
                Instant.now(),
                null
        );
    }

    @BeforeEach
    void setUp() {
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        statusListService = Mockito.mock(StatusListService.class);
        KeyAttestationService keyAttestationService = Mockito.mock(KeyAttestationService.class);
        issuerMetadata = Mockito.mock(IssuerMetadataTechnical.class);
        CredentialFormatFactory credentialFormatFactory = Mockito.mock(CredentialFormatFactory.class);
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
        var offer = getCredentialOffer(CredentialStatusType.IN_PROGRESS, expirationTimeStamp, offerData, uuid, uuid, UUID.randomUUID());
        offer.setTokenExpirationTimestamp(Instant.now().minusSeconds(600).getEpochSecond());

        when(credentialOfferRepository.findByAccessToken(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var credentialRequestDto = new CredentialRequestDto(
                "vc+sd-jwt",
                new HashMap<>(),
                null
        );
        var ex = assertThrows(OAuthException.class, () -> credentialService.createCredential(credentialRequestDto, uuid.toString(), null));

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
        var offer = getCredentialOffer(CredentialStatusType.OFFERED, expirationTimeStamp, offerData, uuid, uuid, UUID.randomUUID());

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
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(Map.of("hello", "world"));
        when(credentialOfferRepository.save(any())).thenAnswer(new Answer<CredentialOffer>() {
            @Override
            public CredentialOffer answer(InvocationOnMock invocation) {
                return invocation.getArgument(0);
            }
        });

        assertDoesNotThrow(() -> credentialService.createCredential(createCredentialRequestDto));
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
}