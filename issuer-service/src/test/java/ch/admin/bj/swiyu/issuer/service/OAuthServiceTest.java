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

import static org.assertj.core.api.Assertions.assertThat;

class OAuthServiceTest {

    private OAuthService oauthService;
    private CredentialOfferRepository credentialOfferRepository;
    private CredentialManagementRepository credentialManagementRepository;
    private ApplicationProperties applicationProperties;
    private CredentialStateMachine credentialStateMachine;

    @BeforeEach
    void setUp() {
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        EventProducerService eventProducerService = Mockito.mock(EventProducerService.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);
        credentialManagementRepository = Mockito.mock(CredentialManagementRepository.class);
        credentialStateMachine = Mockito.mock(CredentialStateMachine.class);
        oauthService = new OAuthService(
                applicationProperties,
                eventProducerService,
                credentialOfferRepository,
                credentialManagementRepository,
                credentialStateMachine
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
    void refreshOAuthToken_whenRotation_thenSuccess() {
        Mockito.when(applicationProperties.isAllowRefreshTokenRotation()).thenReturn(true);
        var credentialOffer = Mockito.mock(CredentialOffer.class);
        Mockito.when(credentialOffer.getNonce()).thenReturn(UUID.randomUUID());
        Mockito.when(credentialOffer.getCredentialStatus()).thenReturn(CredentialOfferStatusType.ISSUED);
        var refreshToken = UUID.randomUUID();
        var mockMgmt = Mockito.mock(CredentialManagement.class);
        Mockito.when(credentialManagementRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.ofNullable(mockMgmt));
        Mockito.when(mockMgmt.getCredentialManagementStatus()).thenReturn(CredentialStatusManagementType.ISSUED);
        Mockito.when(mockMgmt.getId()).thenReturn(UUID.randomUUID());
        Mockito.when(mockMgmt.getCredentialOffers()).thenReturn(Set.of(credentialOffer));
        Mockito.when(mockMgmt.getRefreshToken()).thenReturn(refreshToken);
        // ensure save does not throw
        Mockito.when(credentialManagementRepository.save(mockMgmt)).thenReturn(mockMgmt);

        var newOAuthTokenResponse = Assertions.assertDoesNotThrow(() -> oauthService.refreshOAuthToken(refreshToken.toString()));
        assertThat(newOAuthTokenResponse.getRefreshToken())
                .as("Refresh tokens must have rotated")
                .isNotEqualTo(refreshToken.toString());
        // verify that repository save was called (tokens updated)
        Mockito.verify(credentialManagementRepository).save(mockMgmt);


    }

    @Test
    void refreshOAuthToken_whenNoRotation_thenSuccess() {
        Mockito.when(applicationProperties.isAllowRefreshTokenRotation()).thenReturn(false);
        var credentialOffer = Mockito.mock(CredentialOffer.class);
        Mockito.when(credentialOffer.getNonce()).thenReturn(UUID.randomUUID());
        Mockito.when(credentialOffer.getCredentialStatus()).thenReturn(CredentialOfferStatusType.ISSUED);
        var refreshToken = UUID.randomUUID();
        var mockMgmt = Mockito.mock(CredentialManagement.class);
        Mockito.when(credentialManagementRepository.findByRefreshToken(refreshToken)).thenReturn(Optional.ofNullable(mockMgmt));
        Mockito.when(mockMgmt.getCredentialManagementStatus()).thenReturn(CredentialStatusManagementType.ISSUED);
        Mockito.when(mockMgmt.getId()).thenReturn(UUID.randomUUID());
        Mockito.when(mockMgmt.getCredentialOffers()).thenReturn(Set.of(credentialOffer));
        Mockito.when(mockMgmt.getRefreshToken()).thenReturn(refreshToken);
        // ensure save does not throw
        Mockito.when(credentialManagementRepository.save(mockMgmt)).thenReturn(mockMgmt);

        var newOAuthTokenResponse = Assertions.assertDoesNotThrow(() -> oauthService.refreshOAuthToken(refreshToken.toString()));
        assertThat(newOAuthTokenResponse.getRefreshToken())
                .as("Refresh tokens must remain the same when refresh token rotation is disabled")
                .isEqualTo(refreshToken.toString());
        // verify that repository save was called (tokens updated)
        Mockito.verify(credentialManagementRepository).save(mockMgmt);
    }
}