package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Optional;
import java.util.UUID;

class OAuthServiceTest {

    private OAuthService oauthService;
    private CredentialOfferRepository credentialOfferRepository;
    private ApplicationProperties applicationProperties;

    @BeforeEach
    void setUp() {
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        EventProducerService eventProducerService = Mockito.mock(EventProducerService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);
        oauthService = new OAuthService(
                applicationProperties,
                eventProducerService,
                credentialOfferRepository
        );
        Mockito.when(applicationProperties.getTokenTTL()).thenReturn(3600L);
    }

    @Test
    void refreshOAuthToken_whenRevoked_thenThrowsOAuthException() {
        var refreshToken = UUID.randomUUID();
        var mockOffer = Mockito.mock(CredentialOffer.class);
        Mockito.when(credentialOfferRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.ofNullable(mockOffer));
        Mockito.when(mockOffer.getCredentialStatus()).thenReturn(CredentialStatusType.REVOKED);
        Assertions.assertThrows(OAuthException.class, () -> oauthService.refreshOAuthToken(refreshToken.toString()));
    }

    @Test
    void refreshOAuthToken_thenSuccess() {
        var refreshToken = UUID.randomUUID();
        var mockOffer = Mockito.mock(CredentialOffer.class);
        Mockito.when(credentialOfferRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.ofNullable(mockOffer));
        Mockito.when(mockOffer.getCredentialStatus()).thenReturn(CredentialStatusType.DEFERRED);
        Assertions.assertDoesNotThrow(() -> oauthService.refreshOAuthToken(refreshToken.toString()));
    }
}
