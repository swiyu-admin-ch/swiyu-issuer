/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
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
import org.mockito.Mock;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.*;

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

    @BeforeEach
    void setUp() {
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        OpenIdIssuerConfiguration openIdIssuerConfiguration = Mockito.mock(OpenIdIssuerConfiguration.class);
        NonceService nonceService = Mockito.mock(NonceService.class);
        statusListService = Mockito.mock(StatusListService.class);
        issuerMetadata = Mockito.mock(IssuerMetadataTechnical.class);
        credentialFormatFactory = Mockito.mock(CredentialFormatFactory.class);
        ApplicationProperties applicationProperties = Mockito.mock(ApplicationProperties.class);
        KeyAttestationService keyAttestationService = Mockito.mock(KeyAttestationService.class);
        webhookService = Mockito.mock(WebhookService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);

        credentialService = new CredentialService(
                credentialOfferRepository,
                new ObjectMapper(),
                issuerMetadata,
                credentialFormatFactory,
                applicationProperties,
                webhookService,
                openIdIssuerConfiguration,
                nonceService,
                keyAttestationService
        );

        var statusListToken = new TokenStatusListToken(2, 10000);
        statusList = StatusList.builder().type(StatusListType.TOKEN_STATUS_LIST)
                .config(Map.of("bits", 2))
                .uri("https://localhost:8080/status")
                .statusZipped(statusListToken.getStatusListClaims().get("lst").toString())
                .nextFreeIndex(0)
                .maxLength(10000)
                .build();

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