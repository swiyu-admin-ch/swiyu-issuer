/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredCredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointRequestDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.ProofsDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialClaim;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.*;
import ch.admin.bj.swiyu.issuer.service.renewal.BusinessIssuerRenewalApiClient;
import ch.admin.bj.swiyu.issuer.service.webhook.DeferredEvent;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import ch.admin.bj.swiyu.issuer.service.webhook.OfferStateChangeEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Instant;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.CREDENTIAL_REQUEST_DENIED;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils.getCredentialManagement;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils.getCredentialOffer;
import static java.time.Instant.now;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import static ch.admin.bj.swiyu.issuer.oid4vci.service.CredentialStateMachineTestHelper.mockCredentialStateMachine;

class CredentialServiceTest {
    private final Map<String, Object> offerData = Map.of("hello", "world");
    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock
    CredentialOfferRepository credentialOfferRepository;
    CredentialManagementRepository credentialManagementRepository;
    CredentialService credentialService;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    private StatusListService statusListService;
    private IssuerMetadata issuerMetadata;
    private StatusList statusList;
    private CredentialFormatFactory credentialFormatFactory;
    private ApplicationProperties applicationProperties;
    private HolderBindingService holderBindingService;
    private CredentialConfiguration credentialConfiguration;
    private ApplicationEventPublisher applicationEventPublisher;
    private OAuthService oAuthService;
    private CredentialManagementService credentialManagementService;
    private BusinessIssuerRenewalApiClient renewalApiClient;
    private CredentialStateMachine credentialStateMachine;


    @BeforeEach
    void setUp() {
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        statusListService = Mockito.mock(StatusListService.class);
        issuerMetadata = Mockito.mock(IssuerMetadata.class);
        credentialFormatFactory = Mockito.mock(CredentialFormatFactory.class);
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        holderBindingService = Mockito.mock(HolderBindingService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);
        credentialManagementRepository = Mockito.mock(CredentialManagementRepository.class);
        applicationEventPublisher = Mockito.mock(ApplicationEventPublisher.class);
        credentialManagementService = Mockito.mock(CredentialManagementService.class);
        renewalApiClient = Mockito.mock(BusinessIssuerRenewalApiClient.class);
        credentialStateMachine = Mockito.mock(CredentialStateMachine.class);

        mockCredentialStateMachine(credentialStateMachine);

        EncryptionService encryptionService = Mockito.mock(EncryptionService.class);
        EventProducerService eventProducerService = new EventProducerService(applicationEventPublisher, objectMapper);

        oAuthService = new OAuthService(applicationProperties, eventProducerService, credentialOfferRepository, credentialManagementRepository, credentialStateMachine);

        credentialService = new CredentialService(
                credentialOfferRepository,
                issuerMetadata,
                credentialFormatFactory,
                applicationProperties,
                holderBindingService,
                oAuthService,
                eventProducerService,
                encryptionService,
                credentialManagementRepository,
                renewalApiClient,
                credentialManagementService,
                credentialStateMachine
        );

        var statusListToken = new TokenStatusListToken(2, 10000);
        statusList = StatusList.builder().type(StatusListType.TOKEN_STATUS_LIST)
                .config(Map.of("bits", 2))
                .uri("https://localhost:8080/status")
                .statusZipped(statusListToken.getStatusListClaims().get("lst").toString())
                .maxLength(10000)
                .build();

        credentialConfiguration = mock(CredentialConfiguration.class);
        when(credentialConfiguration.getCredentialDefinition()).thenReturn(null);
        when(credentialConfiguration.getClaims()).thenReturn(Map.of("claim1", new CredentialClaim()));
        when(credentialConfiguration.getFormat()).thenReturn("vc+sd-jwt");
        when(credentialConfiguration.getVct()).thenReturn("test-vct");

        when(issuerMetadata.getCredentialConfigurationById("test")).thenReturn(credentialConfiguration);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test", credentialConfiguration));

        when(encryptionService.issuerMetadataWithEncryptionOptions()).thenReturn(issuerMetadata);

    }

    @Test
    void givenExpiredOffer_whenCredentialIsCreated_throws() {
        // GIVEN
        var uuid = UUID.randomUUID();
        var preAuthorizedCode = UUID.randomUUID();

        var expirationTimeStamp = Instant.now().minusSeconds(10).getEpochSecond();
        var offer = getCredentialOffer(CredentialOfferStatusType.OFFERED, expirationTimeStamp, offerData, uuid, preAuthorizedCode, UUID.randomUUID(), null, null);
        var mgmt = CredentialManagement.builder()
                .accessToken(uuid)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(offer))
                .build();
        offer.setCredentialManagement(mgmt);

        when(credentialManagementRepository.findByAccessToken(uuid)).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        // WHEN credential is created for offer with expired timestamp
        var credentialRequestDto = getCredentialRequestDto();
        var uuidString = uuid.toString();
        var ex = assertThrows(OAuthException.class, () ->
                credentialService.createCredential(credentialRequestDto, uuidString, null));

        // THEN Status is changed and offer data is cleared
        assertEquals(CredentialOfferStatusType.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
        // todo check invalid_grant  vs. invalid access token
        assertEquals("INVALID_GRANT", ex.getError().toString());
        assertEquals("Invalid accessToken", ex.getMessage());
    }

    @Test
    void givenExpiredOffer_whenTokenIsCreated_throwsOAuthException() {
        var uuid = UUID.randomUUID();
        var expirationTimeStamp = Instant.now().minusSeconds(10).getEpochSecond();
        var mgmt = getCredentialManagement(CredentialStatusManagementType.INIT, UUID.randomUUID());
        var offer = getCredentialOffer(CredentialOfferStatusType.OFFERED, expirationTimeStamp, offerData, uuid, uuid, UUID.randomUUID(), null, null);
        offer.setCredentialManagement(mgmt);

        when(credentialOfferRepository.findByPreAuthorizedCode(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var uuidString = uuid.toString();
        var ex = assertThrows(OAuthException.class,
                () -> oAuthService.issueOAuthToken(uuidString));

        // THEN Status is changed and offer data is cleared
        assertEquals(CredentialOfferStatusType.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
        assertEquals("INVALID_GRANT", ex.getError().toString());
        assertEquals("Invalid preAuthCode", ex.getMessage());
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

        var offer = getCredentialOffer(
                CredentialOfferStatusType.IN_PROGRESS,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                null);
        var mgmt = CredentialManagement.builder()
                .accessToken(UUID.randomUUID())
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(offer))
                .build();

        offer.setCredentialManagement(mgmt);

        when(statusListService.findByUriIn(any())).thenReturn(List.of(statusList));
        when(credentialOfferStatusRepository.save(any())).thenReturn(getCredentialOfferStatus(UUID.randomUUID(), UUID.randomUUID()));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("different-test-metadata", mock(CredentialConfiguration.class)));
        when(credentialManagementRepository.findByAccessToken(mgmt.getAccessToken())).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());
        when(issuerMetadata.getCredentialConfigurationById(anyString())).thenReturn(credConfig);

        var accessToken = mgmt.getAccessToken().toString();
        var exception = assertThrows(Oid4vcException.class, () ->
                credentialService.createCredential(credentialRequestDto, accessToken, clientInfo));

        assertTrue(exception.getMessage().contains("Mismatch between requested and offered format."));
    }

    @Test
    void testCreateCredential_deferred() throws JsonProcessingException {

        var credentialRequestDto = getCredentialRequestDto();
        var clientInfo = getClientInfo();

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialOfferStatusType.IN_PROGRESS,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                null);
        var mgmt = CredentialManagement.builder()
                .accessToken(UUID.randomUUID())
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(credentialOffer))
                .build();

        credentialOffer.setCredentialManagement(mgmt);

        when(credentialManagementRepository.findByAccessToken(mgmt.getAccessToken())).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Mock the factory to return the builder
        var sdJwtCredential = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder(anyString())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialOffer(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialResponseEncryption(any(), any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.holderBindings(anyList())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialType(anyList())).thenReturn(sdJwtCredential);
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

        credentialService.createCredential(credentialRequestDto, mgmt.getAccessToken().toString(), clientInfo);

        // check if is issued && data removed
        assertEquals(CredentialOfferStatusType.DEFERRED, credentialOffer.getCredentialStatus());
        String clientInfoString = objectMapper.writeValueAsString(clientInfo);
        var stateChangeEvent = new DeferredEvent(credentialOffer.getId(), clientInfoString);
        verify(applicationEventPublisher).publishEvent(stateChangeEvent);
    }

    @Test
    void testCreateCredentialFromDeferredRequest_notReady_thenException() {

        UUID accessToken = UUID.randomUUID();

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialOfferStatusType.DEFERRED,
                Instant.now().plusSeconds(600).getEpochSecond(),
                Map.of(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                UUID.randomUUID());
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(credentialOffer))
                .build();

        DeferredCredentialEndpointRequestDto deferredRequest = new DeferredCredentialEndpointRequestDto(credentialOffer.getTransactionId());

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Act
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(Oid4vcException.class, () ->
                credentialService.createCredentialFromDeferredRequest(deferredRequest, accessTokenString));

        assertEquals("The credential is not marked as ready to be issued", exception.getMessage());
    }

    @ParameterizedTest
    @EnumSource(value = CredentialOfferStatusType.class, names = {"CANCELLED", "EXPIRED", "ISSUED"})
    void testCreateCredentialFromDeferredRequest_withInvalidStatus_thenException(CredentialOfferStatusType status) {

        UUID accessToken = UUID.randomUUID();

        CredentialOffer credentialOffer = getCredentialOffer(
                status,
                Instant.now().plusSeconds(600).getEpochSecond(),
                Map.of(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                UUID.randomUUID());
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(credentialOffer))
                .build();

        DeferredCredentialEndpointRequestDto deferredRequest = new DeferredCredentialEndpointRequestDto(credentialOffer.getTransactionId());

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Act
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(Oid4vcException.class, () ->
                credentialService.createCredentialFromDeferredRequest(deferredRequest, accessTokenString));

        assertEquals(CREDENTIAL_REQUEST_DENIED, exception.getError());
        assertEquals("The credential can not be issued anymore, the offer was either cancelled or expired", exception.getMessage());
    }

    @Test
    void testCreateCredentialFromDeferredRequest_accesTokenExpired_thenException() {

        UUID transactionId = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        DeferredCredentialEndpointRequestDto deferredRequest = new DeferredCredentialEndpointRequestDto(transactionId);

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialOfferStatusType.DEFERRED,
                Instant.now().minusSeconds(600).getEpochSecond(),
                Map.of(),
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                transactionId);
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().minusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(credentialOffer))
                .build();

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));

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

        DeferredCredentialEndpointRequestDto deferredRequest = new DeferredCredentialEndpointRequestDto(transactionId);

        CredentialOffer credentialOffer = spy(getCredentialOffer(
                CredentialOfferStatusType.READY,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                transactionId));
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(credentialOffer))
                .build();
        credentialOffer.setCredentialManagement(mgmt);

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Mock the factory to return the builder
        var sdJwtCredential = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder(anyString())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialOffer(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialResponseEncryption(any(), any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.holderBindings(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialType(any())).thenReturn(sdJwtCredential);

        // Act
        credentialService.createCredentialFromDeferredRequest(deferredRequest, accessToken.toString());

        // check if is issued && data removed
        assertEquals(CredentialOfferStatusType.ISSUED, credentialOffer.getCredentialStatus());
        assertNull(credentialOffer.getOfferData());
        assertNull(credentialOffer.getTransactionId());
        assertNull(credentialOffer.getHolderJWKs());
        assertNull(credentialOffer.getClientAgentInfo());

        verify(credentialOfferRepository).save(credentialOffer);
        var stateChangeEvent = new OfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), CredentialOfferStatusType.ISSUED);
        verify(applicationEventPublisher).publishEvent(stateChangeEvent);
    }

    @Test
    void testCreateCredentialFromDeferredRequestV2_success() {

        UUID transactionId = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        DeferredCredentialEndpointRequestDto deferredRequest = new DeferredCredentialEndpointRequestDto(transactionId);

        CredentialOffer credentialOffer = spy(getCredentialOffer(
                CredentialOfferStatusType.READY,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                new CredentialOfferMetadata(true, null, null, null),
                transactionId));
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(credentialOffer))
                .build();

        credentialOffer.setCredentialManagement(mgmt);

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Mock the factory to return the builder
        var sdJwtCredential = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder(anyString())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialOffer(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialResponseEncryption(any(), any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.holderBindings(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialType(any())).thenReturn(sdJwtCredential);

        // Act
        credentialService.createCredentialFromDeferredRequestV2(deferredRequest, accessToken.toString());

        // check if is issued && data removed
        assertEquals(CredentialOfferStatusType.ISSUED, credentialOffer.getCredentialStatus());
        assertNull(credentialOffer.getOfferData());
        assertNull(credentialOffer.getTransactionId());
        assertNull(credentialOffer.getHolderJWKs());
        assertNull(credentialOffer.getClientAgentInfo());

        verify(credentialOfferRepository).save(credentialOffer);
        var stateChangeEvent = new OfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), CredentialOfferStatusType.ISSUED);
        verify(applicationEventPublisher).publishEvent(stateChangeEvent);
    }

    @Test
    void issueOAuthToken_thenSuccess() {
        UUID preAuthCode = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialOfferStatusType.OFFERED,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                null, null);

        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(credentialOffer))
                .credentialManagementStatus(CredentialStatusManagementType.INIT)
                .build();

        credentialOffer.setCredentialManagement(mgmt);
        when(credentialOfferRepository.findByPreAuthorizedCode(preAuthCode)).thenReturn(Optional.of(credentialOffer));
        when(applicationProperties.getTokenTTL()).thenReturn(600L);

        OAuthTokenDto token = oAuthService.issueOAuthToken(preAuthCode.toString());

        assertEquals(mgmt.getAccessToken().toString(), token.getAccessToken());
        assertEquals(600, token.getExpiresIn());
        assertEquals(credentialOffer.getNonce().toString(), token.getCNonce());
        verify(credentialManagementRepository).save(mgmt);
        var stateChangeEvent = new OfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());
        verify(applicationEventPublisher).publishEvent(stateChangeEvent);
    }

    @Test
    void issueOAuthToken_invalidStatus_throwsException() {
        UUID preAuthCode = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialOfferStatusType.READY,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                null, null);
        when(credentialOfferRepository.findByPreAuthorizedCode(preAuthCode)).thenReturn(Optional.of(credentialOffer));
        when(applicationProperties.getTokenTTL()).thenReturn(600L);

        var preAuthCodeString = preAuthCode.toString();
        var exception = assertThrows(OAuthException.class, () -> oAuthService.issueOAuthToken(preAuthCodeString));

        assertEquals("Credential has already been used", exception.getMessage());
    }

    @Test
    void createCredentialV2_deferred_thenSuccess() throws JsonProcessingException {
        // Arrange
        CredentialEndpointRequestDtoV2 requestDto = mock(CredentialEndpointRequestDtoV2.class);
        UUID accessToken = UUID.randomUUID();

        CredentialRequestClass credentialRequest = mock(CredentialRequestClass.class);
        ClientAgentInfo clientInfo = mock(ClientAgentInfo.class);

        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .build();

        CredentialOffer offer = mockCredentialOffer(true, mgmt);

        mgmt.setCredentialOffers(Set.of(offer));


        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.of(offer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());
        when(applicationProperties.getMinDeferredOfferIntervalSeconds()).thenReturn(600L);

        List<ProofJwt> proofs = List.of(mock(ProofJwt.class));
        when(credentialRequest.getProofs(anyInt(), anyInt())).thenReturn(proofs);
        when(holderBindingService.getValidateHolderPublicKeys(credentialRequest, offer)).thenReturn(proofs);

        mockVCBuilder(offer);
        when(issuerMetadata.getCredentialConfigurationById(anyString())).thenReturn(credentialConfiguration);

        credentialService.createCredentialV2(requestDto, accessToken.toString(), clientInfo, null);

        verify(offer).initializeDeferredState(any(), any(), anyList(), anyList(), any(), any());
        verify(credentialOfferRepository).save(offer);
        var stateChangeEvent = new DeferredEvent(offer.getId(), objectMapper.writeValueAsString(clientInfo));
        verify(applicationEventPublisher).publishEvent(stateChangeEvent);
    }

    @Test
    void createCredentialV2_nonDeferred_thenSuccess() {
        // Arrange
        CredentialEndpointRequestDtoV2 requestDto = mock(CredentialEndpointRequestDtoV2.class);
        UUID accessToken = UUID.randomUUID();
        var proofs = List.of(mock(ProofJwt.class));

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder()
                .credentialConfigurationId("test")
                .format("vc+sd-jwt")
                .proof(Map.of("proofs", proofs))
                .build();
        ClientAgentInfo clientInfo = mock(ClientAgentInfo.class);

        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .build();

        CredentialOffer offer = mockCredentialOffer(false, mgmt);

        mgmt.setCredentialOffers(Set.of(offer));

        offer.setCredentialManagement(mgmt);
        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.of(offer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        when(holderBindingService.getValidateHolderPublicKeys(credentialRequest, offer)).thenReturn(proofs);

        mockVCBuilder(offer);
        when(issuerMetadata.getCredentialConfigurationById(anyString())).thenReturn(credentialConfiguration);

        credentialService.createCredentialV2(requestDto, accessToken.toString(), clientInfo, null);

        verify(credentialOfferRepository, atLeastOnce()).save(offer);
        var stateChangeEvent = new OfferStateChangeEvent(mgmt.getId(), offer.getId(), CredentialOfferStatusType.IN_PROGRESS);
        verify(applicationEventPublisher).publishEvent(stateChangeEvent);
    }

    @Test
    void issueOAuthToken_withInvalidUUIDPreAuthCode_throwsOAuthException() {
        var invalidPreAuthCode = "definitely-not-a-uuid";

        var exception = assertThrows(OAuthException.class, () ->
                oAuthService.issueOAuthToken(invalidPreAuthCode));

        assertEquals("INVALID_REQUEST", exception.getError().toString());
        assertEquals("Expecting a correct UUID", exception.getMessage());
    }

    @Test
    void createCredentialFromDeferredRequest_withInvalidTransactionId_throwsOAuthException() {
        UUID accessToken = UUID.randomUUID();
        UUID transactionId = UUID.randomUUID();
        var expirationTimeStamp = now().plusSeconds(1000).getEpochSecond();
        DeferredCredentialEndpointRequestDto deferredRequest = new DeferredCredentialEndpointRequestDto(transactionId);
        var offer = getCredentialOffer(CredentialOfferStatusType.IN_PROGRESS, expirationTimeStamp, offerData, accessToken, UUID.randomUUID(), UUID.randomUUID(), null, UUID.randomUUID());
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(offer))
                .build();

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(Oid4vcException.class, () -> credentialService.createCredentialFromDeferredRequest(deferredRequest, accessTokenString));

        assertEquals(CredentialRequestError.INVALID_TRANSACTION_ID, exception.getError());
        assertEquals("Invalid transactional id", exception.getMessage());
    }

    @Test
    void createCredentialFromDeferredRequest_withExpiredOffer_throwsOAuthException() {
        UUID accessToken = UUID.randomUUID();
        UUID transactionId = UUID.randomUUID();
        var expirationTimeStamp = now().minusSeconds(1).getEpochSecond();
        DeferredCredentialEndpointRequestDto deferredRequest = new DeferredCredentialEndpointRequestDto(transactionId);
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(expirationTimeStamp)
                .build();
        var offer = getCredentialOffer(CredentialOfferStatusType.READY, expirationTimeStamp, offerData, accessToken, UUID.randomUUID(), UUID.randomUUID(), null, transactionId);
        offer.setCredentialManagement(mgmt);
        mgmt.setCredentialOffers(Set.of(offer));

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(OAuthException.class, () -> credentialService.createCredentialFromDeferredRequest(deferredRequest, accessTokenString));

        assertEquals(OAuthError.INVALID_TOKEN, exception.getError());
        assertEquals("Invalid accessToken", exception.getMessage());
    }

    @ParameterizedTest
    @EnumSource(value = CredentialOfferStatusType.class, names = {"CANCELLED", "EXPIRED", "READY", "DEFERRED"})
    void createCredentialEnvelopeDto_withInvalidSatus_throwsOAuthException(CredentialOfferStatusType status) {
        UUID accessToken = UUID.randomUUID();
        UUID transactionId = UUID.randomUUID();
        var expirationTimeStamp = now().plusSeconds(100).getEpochSecond();
        var credentialRequestDto = getCredentialRequestDto();
        var offer = getCredentialOffer(status, expirationTimeStamp, offerData, accessToken, UUID.randomUUID(), UUID.randomUUID(), null, transactionId);
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(expirationTimeStamp)
                .credentialOffers(Set.of(offer))
                .build();
        offer.setCredentialManagement(mgmt);

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(OAuthException.class, () -> credentialService.createCredential(credentialRequestDto, accessTokenString, null));

        assertEquals(OAuthError.INVALID_GRANT, exception.getError());
    }

    @Test
    void createCredentialEnvelopeDto_withUnsupportedCredentialType_throwsOAuthException() {
        UUID accessToken = UUID.randomUUID();
        UUID transactionId = UUID.randomUUID();
        var expirationTimeStamp = now().plusSeconds(100).getEpochSecond();
        CredentialEndpointRequestDtoV2 credentialRequestDto = getCredentialRequestDtoV2("not-test", null);
        var offer = getCredentialOffer(CredentialOfferStatusType.IN_PROGRESS, expirationTimeStamp, offerData, accessToken, UUID.randomUUID(), UUID.randomUUID(), null, transactionId);
        var config = mock(CredentialConfiguration.class);
        var mgmt = CredentialManagement.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .credentialOffers(Set.of(offer))
                .build();
        offer.setCredentialManagement(mgmt);
        when(config.getFormat()).thenReturn("vc+sd-jwt");

        when(credentialManagementRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mgmt));
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(Oid4vcException.class, () -> credentialService.createCredentialV2(credentialRequestDto, accessTokenString, null, null));

        assertEquals(CredentialRequestError.UNSUPPORTED_CREDENTIAL_TYPE, exception.getError());
        assertEquals("Mismatch between requested and offered credential configuration id.", exception.getMessage());
    }

    private CredentialOffer mockCredentialOffer(boolean isDeferred, CredentialManagement mgmt) {
        CredentialOffer credentialOffer = mock(CredentialOffer.class);

        when(credentialOffer.getCredentialStatus()).thenReturn(CredentialOfferStatusType.IN_PROGRESS);
        when(credentialOffer.getMetadataCredentialSupportedId()).thenReturn(List.of("test"));

        if (isDeferred) {
            when(credentialOffer.isDeferredOffer()).thenReturn(true);
        } else {
            when(credentialOffer.isDeferredOffer()).thenReturn(false);
        }
        when(credentialOffer.getTransactionId()).thenReturn(UUID.randomUUID());
        when(credentialOffer.getNonce()).thenReturn(UUID.randomUUID());
        when(credentialOffer.getCredentialManagement()).thenReturn(mgmt);

        return credentialOffer;
    }

    private void mockVCBuilder(CredentialOffer credentialOffer) {
        SdJwtCredential vcBuilder = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder("test")).thenReturn(vcBuilder);
        when(vcBuilder.credentialOffer(credentialOffer)).thenReturn(vcBuilder);
        when(vcBuilder.credentialResponseEncryption(any(), any())).thenReturn(vcBuilder);
        when(vcBuilder.holderBindings(anyList())).thenReturn(vcBuilder);
        when(vcBuilder.credentialType(anyList())).thenReturn(vcBuilder);

        CredentialEnvelopeDto deferredEnvelope = mock(CredentialEnvelopeDto.class);
        when(vcBuilder.buildDeferredCredentialV2(any(UUID.class))).thenReturn(deferredEnvelope);

        CredentialEnvelopeDto issuedEnvelope = mock(CredentialEnvelopeDto.class);
        when(vcBuilder.buildCredentialEnvelopeV2()).thenReturn(issuedEnvelope);
    }

    private CredentialOfferStatus getCredentialOfferStatus(UUID offerId, UUID statusId) {
        return CredentialOfferStatus.builder()
                .id(new CredentialOfferStatusKey(offerId, statusId, 1))
                .build();
    }

    private @NotNull CredentialEndpointRequestDto getCredentialRequestDto() {
        return new CredentialEndpointRequestDto(
                "vc+sd-jwt",
                new HashMap<>(),
                null
        );
    }

    private @NotNull CredentialEndpointRequestDtoV2 getCredentialRequestDtoV2(String credentialConfigurationId, ProofsDto proofs) {
        return new CredentialEndpointRequestDtoV2(
                credentialConfigurationId,
                proofs,
                null
        );
    }

    private @NotNull ClientAgentInfo getClientInfo() {
        return new ClientAgentInfo("test-agent", "1.0", "test-client", "test-client-id");
    }
}

