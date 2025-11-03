package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Service for performing OAuth 2.0 Authorization Server related tasks
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class OAuthService {
    private final ApplicationProperties applicationProperties;
    private final EventProducerService eventProducerService;
    private final CredentialOfferRepository credentialOfferRepository;

    /**
     * Issues an OAuth token for a given pre-authorization code created by issuer
     * mgmt
     *
     * @param preAuthCode Pre-authorization code of holder
     * @return OAuth authorization token which can be used in credential service
     * endpoint
     * @throws OAuthException if no offer was found with associated pre-auth_code
     */
    @Transactional
    public OAuthTokenDto issueOAuthToken(String preAuthCode) {
        var offer = getCredentialOfferByPreAuthCode(preAuthCode);

        if (offer.getCredentialStatus() != CredentialStatusType.OFFERED) {
            log.debug("Refused to issue OAuth token. Credential offer {} has already state {}.", offer.getId(),
                    offer.getCredentialStatus());
            throw OAuthException.invalidGrant("Credential has already been used");
        }
        log.info("Pre-Authorized code consumed, sending Access Token {}. Management ID is {} and new status is {}",
                offer.getAccessToken(), offer.getId(), offer.getCredentialStatus());
        offer.markAsInProgress();
        OAuthTokenDto oauthTokenResponse = updateOAuthTokens(offer);
        eventProducerService.produceStateChangeEvent(offer.getId(), offer.getCredentialStatus());
        return oauthTokenResponse;
    }

    @Transactional
    public CredentialOffer getCredentialOfferByAccessToken(String accessToken) {
        var uuid = uuidOrException(accessToken);
        return getNonExpiredCredentialOffer(credentialOfferRepository.findByAccessToken(uuid))
                .orElseThrow(() -> OAuthException.invalidToken("Invalid accessToken"));
    }

    /**
     * Use OAuth 2.0 refresh_token to get a fresh access_token and refresh_token
     *
     * @param refreshToken old refresh token
     * @return OAuth2.0 response with access_token and refresh_token
     * @throws OAuthException if no offer was found with associated refresh_token
     */
    @Transactional
    public OAuthTokenDto refreshOAuthToken(String refreshToken) {
        var offer = getUnrevokedCredentialOfferByRefreshToken(refreshToken);
        log.info("Refreshing OAuth 2.0 token with refresh_token {}. Management ID is {} and associated status is {}",
                refreshToken, offer.getId(), offer.getCredentialStatus());
        offer.setTokenIssuanceTimestamp(applicationProperties.getTokenTTL());
        return updateOAuthTokens(offer);
    }

    /**
     * Update the OAuth 2.0 access_token and refresh_token
     *
     * @param offer credential offer which is being updated
     * @return OAuthTokenDto with the new access and refresh token
     */
    private OAuthTokenDto updateOAuthTokens(CredentialOffer offer) {
        offer.setTokenIssuanceTimestamp(applicationProperties.getTokenTTL());
        offer.setAccessToken(UUID.randomUUID());
        OAuthTokenDto.OAuthTokenDtoBuilder oauthTokenResponseBuilder = OAuthTokenDto.builder()
                .accessToken(offer.getAccessToken().toString())
                .expiresIn(applicationProperties.getTokenTTL())
                .cNonce(offer.getNonce().toString());
        if (applicationProperties.isAllowTokenRefresh()) {
            var newRefreshToken = UUID.randomUUID();
            offer.setRefreshToken(newRefreshToken);
            oauthTokenResponseBuilder.refreshToken(newRefreshToken.toString());
        }
        credentialOfferRepository.save(offer);
        return oauthTokenResponseBuilder.build();
    }

    private CredentialOffer getUnrevokedCredentialOfferByRefreshToken(String refreshToken) {
        var uuid = uuidOrException(refreshToken);
        return getNonRevokedCredentialOffer(credentialOfferRepository.findByRefreshToken(uuid)).orElseThrow(() -> OAuthException.invalidToken("Invalid refresh token"));
    }

    private CredentialOffer getCredentialOfferByPreAuthCode(String preAuthCode) {
        var uuid = uuidOrException(preAuthCode);
        return getNonExpiredCredentialOffer(credentialOfferRepository.findByPreAuthorizedCode(uuid))
                .orElseThrow(() -> OAuthException.invalidGrant("Invalid preAuthCode"));
    }

    private Optional<CredentialOffer> getNonRevokedCredentialOffer(Optional<CredentialOffer> credentialOffer) {
        return credentialOffer.filter(offer -> offer.getCredentialStatus() != CredentialStatusType.REVOKED);
    }

    private Optional<CredentialOffer> getNonExpiredCredentialOffer(Optional<CredentialOffer> credentialOffer) {
        return credentialOffer
                .map(offer -> {
                    if (offer.getCredentialStatus() != CredentialStatusType.EXPIRED
                            && offer.hasExpirationTimeStampPassed()) {
                        offer.markAsExpired();
                        return credentialOfferRepository.save(offer);
                    }
                    return offer;
                });
    }

    private UUID uuidOrException(String preAuthCode) {
        try {
            return UUID.fromString(preAuthCode);
        } catch (IllegalArgumentException ex) {
            throw OAuthException.invalidRequest("Expecting a correct UUID");
        }
    }
}
