package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

class OAuthServiceTest {

    private OAuthService oauthService;
    private CredentialOfferRepository credentialOfferRepository;
    private CredentialManagementRepository credentialManagementRepository;
    private ApplicationProperties applicationProperties;

    @BeforeEach
    void setUp() {
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        EventProducerService eventProducerService = Mockito.mock(EventProducerService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);
        credentialManagementRepository = Mockito.mock(CredentialManagementRepository.class);
        oauthService = new OAuthService(
                applicationProperties,
                eventProducerService,
                credentialOfferRepository,
                credentialManagementRepository
        );
        Mockito.when(applicationProperties.getTokenTTL()).thenReturn(3600L);
        Mockito.when(applicationProperties.isAllowTokenRefresh()).thenReturn(true);
    }

    @Test
    void refreshOAuthToken_whenRevoked_thenThrowsOAuthException() {
        var refreshToken = UUID.randomUUID();
        var mockMgmt = Mockito.mock(CredentialManagement.class);
        Mockito.when(credentialManagementRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.ofNullable(mockMgmt));
        Mockito.when(mockMgmt.getCredentialManagementStatus()).thenReturn(CredentialStatusManagementType.REVOKED);
        var refreshTokenString = refreshToken.toString();
        Assertions.assertThrows(OAuthException.class, () -> oauthService.refreshOAuthToken(refreshTokenString));
    }

    @Test
    void refreshOAuthToken_thenSuccess() {
        var credentialOffer = Mockito.mock(CredentialOffer.class);
        Mockito.when(credentialOffer.getNonce()).thenReturn(UUID.randomUUID());
        Mockito.when(credentialOffer.getCredentialStatus()).thenReturn(CredentialOfferStatusType.ISSUED);
        var refreshToken = UUID.randomUUID();
        var mockMgmt = Mockito.mock(CredentialManagement.class);
        Mockito.when(credentialManagementRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.ofNullable(mockMgmt));
        Mockito.when(mockMgmt.getCredentialManagementStatus()).thenReturn(CredentialStatusManagementType.ISSUED);
        Mockito.when(mockMgmt.getId()).thenReturn(UUID.randomUUID());
        Mockito.when(mockMgmt.getCredentialOffers()).thenReturn(Set.of(credentialOffer));
        // ensure save does not throw
        Mockito.when(credentialManagementRepository.save(mockMgmt)).thenReturn(mockMgmt);

        Assertions.assertDoesNotThrow(() -> oauthService.refreshOAuthToken(refreshToken.toString()));
        // verify that repository save was called (tokens updated)
        Mockito.verify(credentialManagementRepository).save(mockMgmt);
    }
}