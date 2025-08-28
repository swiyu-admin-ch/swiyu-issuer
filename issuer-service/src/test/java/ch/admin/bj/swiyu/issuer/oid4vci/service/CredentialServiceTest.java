/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialRequestDtoV2;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
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
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.CREDENTIAL_REQUEST_DENIED;
import static java.time.Instant.now;
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
    private IssuerMetadataTechnical issuerMetadata;
    private WebhookService webhookService;
    private StatusList statusList;
    private CredentialFormatFactory credentialFormatFactory;
    private ApplicationProperties applicationProperties;
    private HolderBindingService holderBindingService;
    private CredentialConfiguration credentialConfiguration;

    @BeforeEach
    void setUp() {
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        statusListService = Mockito.mock(StatusListService.class);
        issuerMetadata = Mockito.mock(IssuerMetadataTechnical.class);
        credentialFormatFactory = Mockito.mock(CredentialFormatFactory.class);
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        holderBindingService = Mockito.mock(HolderBindingService.class);
        webhookService = Mockito.mock(WebhookService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);

        credentialService = new CredentialService(
                credentialOfferRepository,
                new ObjectMapper(),
                issuerMetadata,
                credentialFormatFactory,
                applicationProperties,
                webhookService,
                holderBindingService
        );

        var statusListToken = new TokenStatusListToken(2, 10000);
        statusList = StatusList.builder().type(StatusListType.TOKEN_STATUS_LIST)
                .config(Map.of("bits", 2))
                .uri("https://localhost:8080/status")
                .statusZipped(statusListToken.getStatusListClaims().get("lst").toString())
                .nextFreeIndex(0)
                .maxLength(10000)
                .build();

        credentialConfiguration = mock(CredentialConfiguration.class);
        when(credentialConfiguration.getCredentialDefinition()).thenReturn(null);
        when(credentialConfiguration.getClaims()).thenReturn(Map.of("claim1", new CredentialClaim()));
        when(credentialConfiguration.getFormat()).thenReturn("vc+sd-jwt");
        when(credentialConfiguration.getVct()).thenReturn("test-vct");

        when(issuerMetadata.getCredentialConfigurationById("test-metadata")).thenReturn(credentialConfiguration);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("test-metadata", credentialConfiguration));

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
    void givenExpiredOffer_whenTokenIsCreated_throwsOAuthException() {
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
        when(issuerMetadata.getCredentialConfigurationById(anyString())).thenReturn(credConfig);

        var accessToken = credentialOffer.getAccessToken().toString();
        var exception = assertThrows(Oid4vcException.class, () ->
                credentialService.createCredential(credentialRequestDto, accessToken, clientInfo));

        assertTrue(exception.getMessage().contains("Mismatch between requested and offered format."));
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

        credentialService.createCredential(credentialRequestDto, credentialOffer.getAccessToken().toString(), clientInfo);

        // check if is issued && data removed
        assertEquals(CredentialStatusType.DEFERRED, credentialOffer.getCredentialStatus());
        String clientInfoString = objectMapper.writeValueAsString(clientInfo);
        verify(webhookService).produceDeferredEvent(credentialOffer.getId(), clientInfoString);
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

        DeferredCredentialRequestDto deferredRequest = new DeferredCredentialRequestDto(credentialOffer.getTransactionId());

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Act
        var accessTokenString = accessToken.toString();
        var exception = assertThrows(Oid4vcException.class, () ->
                credentialService.createCredentialFromDeferredRequest(deferredRequest, accessTokenString));

        assertEquals("The credential is not marked as ready to be issued", exception.getMessage());
    }

    @ParameterizedTest
    @EnumSource(value = CredentialStatusType.class, names = {"CANCELLED", "EXPIRED", "ISSUED", "REVOKED", "SUSPENDED"})
    void testCreateCredentialFromDeferredRequest_withInvalidStatus_thenException(CredentialStatusType status) {

        UUID accessToken = UUID.randomUUID();

        CredentialOffer credentialOffer = getCredentialOffer(
                status,
                Instant.now().plusSeconds(600).getEpochSecond(),
                Map.of(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                Map.of("deferred", true),
                UUID.randomUUID());

        DeferredCredentialRequestDto deferredRequest = new DeferredCredentialRequestDto(credentialOffer.getTransactionId());

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));
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

        DeferredCredentialRequestDto deferredRequest = new DeferredCredentialRequestDto(transactionId);

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

        DeferredCredentialRequestDto deferredRequest = new DeferredCredentialRequestDto(transactionId);

        CredentialOffer credentialOffer = spy(getCredentialOffer(
                CredentialStatusType.READY,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                Map.of("deferred", true),
                transactionId));

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Mock the factory to return the builder
        var sdJwtCredential = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder(anyString())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialOffer(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialResponseEncryption(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.holderBindings(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialType(any())).thenReturn(sdJwtCredential);

        // Act
        credentialService.createCredentialFromDeferredRequest(deferredRequest, accessToken.toString());

        // check if is issued && data removed
        assertEquals(CredentialStatusType.ISSUED, credentialOffer.getCredentialStatus());
        assertNull(credentialOffer.getOfferData());
        assertNull(credentialOffer.getTransactionId());
        assertNull(credentialOffer.getHolderJWKs());
        assertNull(credentialOffer.getClientAgentInfo());

        verify(credentialOfferRepository).save(credentialOffer);
        verify(webhookService).produceStateChangeEvent(any(), any());
        verify(credentialOffer).markAsIssued();
    }

    @Test
    void testCreateCredentialFromDeferredRequestV2_success() {

        UUID transactionId = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        DeferredCredentialRequestDto deferredRequest = new DeferredCredentialRequestDto(transactionId);

        CredentialOffer credentialOffer = spy(getCredentialOffer(
                CredentialStatusType.READY,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                Map.of("deferred", true),
                transactionId));

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        // Mock the factory to return the builder
        var sdJwtCredential = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder(anyString())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialOffer(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialResponseEncryption(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.holderBindings(any())).thenReturn(sdJwtCredential);
        when(sdJwtCredential.credentialType(any())).thenReturn(sdJwtCredential);

        // Act
        credentialService.createCredentialFromDeferredRequestV2(deferredRequest, accessToken.toString());

        // check if is issued && data removed
        assertEquals(CredentialStatusType.ISSUED, credentialOffer.getCredentialStatus());
        assertNull(credentialOffer.getOfferData());
        assertNull(credentialOffer.getTransactionId());
        assertNull(credentialOffer.getHolderJWKs());
        assertNull(credentialOffer.getClientAgentInfo());

        verify(credentialOfferRepository).save(credentialOffer);
        verify(webhookService).produceStateChangeEvent(any(), any());
        verify(credentialOffer).markAsIssued();
    }

    @Test
    void issueOAuthToken_thenSuccess() {
        UUID preAuthCode = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialStatusType.OFFERED,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                null, null);
        when(credentialOfferRepository.findByPreAuthorizedCode(preAuthCode)).thenReturn(Optional.of(credentialOffer));
        when(applicationProperties.getTokenTTL()).thenReturn(600L);

        OAuthTokenDto token = credentialService.issueOAuthToken(preAuthCode.toString());

        assertEquals(credentialOffer.getAccessToken().toString(), token.getAccessToken());
        assertEquals(600, token.getExpiresIn());
        assertEquals(credentialOffer.getNonce().toString(), token.getCNonce());
        verify(credentialOfferRepository).save(credentialOffer);
        verify(webhookService).produceStateChangeEvent(credentialOffer.getId(), credentialOffer.getCredentialStatus());
    }

    @Test
    void issueOAuthToken_invalidStatus_throwsException() {
        UUID preAuthCode = UUID.randomUUID();
        UUID accessToken = UUID.randomUUID();

        CredentialOffer credentialOffer = getCredentialOffer(
                CredentialStatusType.READY,
                Instant.now().plusSeconds(600).getEpochSecond(),
                offerData,
                accessToken,
                UUID.randomUUID(),
                UUID.randomUUID(),
                null, null);
        when(credentialOfferRepository.findByPreAuthorizedCode(preAuthCode)).thenReturn(Optional.of(credentialOffer));
        when(applicationProperties.getTokenTTL()).thenReturn(600L);

        var preAuthCodeString = preAuthCode.toString();
        var exception = assertThrows(OAuthException.class, () -> credentialService.issueOAuthToken(preAuthCodeString));

        assertEquals("Credential has already been used", exception.getMessage());
    }

    @Test
    void createCredentialV2_deferred_thenSuccess() {
        // Arrange
        CredentialRequestDtoV2 requestDto = mock(CredentialRequestDtoV2.class);
        UUID accessToken = UUID.randomUUID();

        CredentialRequestClass credentialRequest = mock(CredentialRequestClass.class);
        ClientAgentInfo clientInfo = mock(ClientAgentInfo.class);

        CredentialOffer credentialOffer = mockCredentialOffer(accessToken, true);

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        List<ProofJwt> proofs = List.of(mock(ProofJwt.class));
        when(credentialRequest.getProofs(anyInt(), anyInt())).thenReturn(proofs);
        when(holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer)).thenReturn(proofs);

        mockVCBuilder(credentialOffer);
        when(issuerMetadata.getCredentialConfigurationById(anyString())).thenReturn(credentialConfiguration);

        credentialService.createCredentialV2(requestDto, accessToken.toString(), clientInfo);

        verify(credentialOffer).markAsDeferred(any(), any(), anyList(), anyList(), any());
        verify(credentialOfferRepository).save(credentialOffer);
        verify(webhookService).produceDeferredEvent(any(), any());
    }

    @Test
    void createCredentialV2_nonDeferred_thenSuccess() {
        // Arrange
        CredentialRequestDtoV2 requestDto = mock(CredentialRequestDtoV2.class);
        UUID accessToken = UUID.randomUUID();

        CredentialRequestClass credentialRequest = mock(CredentialRequestClass.class);
        ClientAgentInfo clientInfo = mock(ClientAgentInfo.class);
        CredentialOffer credentialOffer = mockCredentialOffer(accessToken, false);

        when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByIdForUpdate(any(UUID.class))).thenReturn(Optional.of(credentialOffer));
        when(credentialOfferRepository.findByPreAuthorizedCode(any(UUID.class))).thenReturn(Optional.empty());

        List<ProofJwt> proofs = List.of(mock(ProofJwt.class));
        when(credentialRequest.getProofs(anyInt(), anyInt())).thenReturn(proofs);

        when(holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer)).thenReturn(proofs);

        mockVCBuilder(credentialOffer);
        when(issuerMetadata.getCredentialConfigurationById(anyString())).thenReturn(credentialConfiguration);

        credentialService.createCredentialV2(requestDto, accessToken.toString(), clientInfo);

        verify(credentialOffer).markAsIssued();
        verify(credentialOfferRepository, atLeastOnce()).save(credentialOffer);
        verify(webhookService).produceStateChangeEvent(any(), any());
    }

    private CredentialOffer mockCredentialOffer(UUID accessToken, boolean isDeferred) {
        CredentialOffer credentialOffer = mock(CredentialOffer.class);

        when(credentialOffer.getCredentialStatus()).thenReturn(CredentialStatusType.IN_PROGRESS);
        when(credentialOffer.getMetadataCredentialSupportedId()).thenReturn(List.of("test-metadata"));

        when(credentialOffer.getAccessToken()).thenReturn(accessToken);
        if (isDeferred) {
            when(credentialOffer.isDeferredOffer()).thenReturn(true);
        } else {
            when(credentialOffer.isDeferredOffer()).thenReturn(false);
        }
        when(credentialOffer.getTransactionId()).thenReturn(UUID.randomUUID());
        when(credentialOffer.getNonce()).thenReturn(UUID.randomUUID());

        return credentialOffer;
    }

    private void mockVCBuilder(CredentialOffer credentialOffer) {
        SdJwtCredential vcBuilder = mock(SdJwtCredential.class);
        when(credentialFormatFactory.getFormatBuilder("test-metadata")).thenReturn(vcBuilder);
        when(vcBuilder.credentialOffer(credentialOffer)).thenReturn(vcBuilder);
        when(vcBuilder.credentialResponseEncryption(any())).thenReturn(vcBuilder);
        when(vcBuilder.holderBindings(anyList())).thenReturn(vcBuilder);
        when(vcBuilder.credentialType(anyList())).thenReturn(vcBuilder);

        CredentialEnvelopeDto deferredEnvelope = mock(CredentialEnvelopeDto.class);
        when(vcBuilder.buildDeferredCredentialV2(any(UUID.class))).thenReturn(deferredEnvelope);

        CredentialEnvelopeDto issuedEnvelope = mock(CredentialEnvelopeDto.class);
        when(vcBuilder.buildCredentialEnvelopeV2()).thenReturn(issuedEnvelope);
    }

    private CredentialOfferStatus getCredentialOfferStatus(UUID offerId, UUID statusId) {
        return CredentialOfferStatus.builder()
                .id(new CredentialOfferStatusKey(offerId, statusId))
                .index(1)
                .build();
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
                null,
                Instant.now().plusSeconds(600).getEpochSecond(),
                nonce,
                preAuthorizedCode,
                offerExpirationTimestamp,
                Instant.now(),
                Instant.now(),
                new CredentialRequestClass("vc+sd-jwt", null, null),
                null
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