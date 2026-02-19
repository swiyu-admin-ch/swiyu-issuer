package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenDto;
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
    private final CredentialManagementRepository credentialManagementRepository;
    private final CredentialStateMachine credentialStateMachine;

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
        var mgmt = offer.getCredentialManagement();

        if (offer.getCredentialStatus() != CredentialOfferStatusType.OFFERED) {
            log.debug("Refused to issue OAuth token. Credential offer {} has already state {}.", offer.getId(),
                    offer.getCredentialStatus());
            throw OAuthException.invalidGrant("Credential has already been used");
        }
        log.info("Pre-Authorized code consumed, sending Access Token {}. Management ID is {}, offer ID is {} and new status is {}",
                mgmt.getAccessToken(), mgmt.getId(), offer.getId(), offer.getCredentialStatus());
        credentialStateMachine.sendEventAndUpdateStatus(offer, CredentialStateMachineConfig.CredentialOfferEvent.CLAIM);
        return updateOAuthTokens(mgmt);
    }

    /**
     * Get Credential Management by access token
     *
     * @param accessToken OAuth 2.0 access token
     * @return CredentialManagement associated with the access token
     * @throws OAuthException if no offer was found with associated access_token
     */
    @Transactional
    public CredentialManagement getCredentialManagementByAccessToken(String accessToken) {
        var uuid = uuidOrException(accessToken);
        var mgmt = credentialManagementRepository.findByAccessToken(uuid);

        // check expiration
        if (mgmt.isEmpty() || mgmt.get().hasTokenExpirationPassed()) {
            throw OAuthException.invalidToken("Invalid accessToken");
        }

        return mgmt.get();
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
        var credentialManagement = getUnrevokedCredentialOfferByRefreshToken(refreshToken);
        log.info("Refreshing OAuth 2.0 token for Management ID is {} and associated status is {}",
                credentialManagement.getId(), credentialManagement.getCredentialManagementStatus());
        credentialManagement.setTokenIssuanceTimestamp(applicationProperties.getTokenTTL());
        return updateOAuthTokens(credentialManagement);
    }

    /**
     * Retrieve a non-revoked CredentialManagement by its refresh token.
     * <p>
     * Validates that the provided refresh token is a UUID, looks up the
     * corresponding CredentialManagement and ensures it is not in the
     * \`REVOKED\` state.
     *
     * @param refreshToken the refresh token string (expected UUID)
     * @return the matching non-revoked CredentialManagement
     * @throws OAuthException if the token is not a valid UUID or no non-revoked credential is found
     */
    @Transactional
    public CredentialManagement getUnrevokedCredentialOfferByRefreshToken(String refreshToken) {
        var uuid = uuidOrException(refreshToken);
        return getNonRevokedCredentialOffer(credentialManagementRepository.findByRefreshToken(uuid)).orElseThrow(() -> OAuthException.invalidToken("Invalid refresh token"));
    }

    /**
     * Update the OAuth 2.0 access_token and refresh_token
     *
     * @param mgmt credential offer which is being updated
     * @return OAuthTokenDto with the new access and refresh token
     */
    private OAuthTokenDto updateOAuthTokens(CredentialManagement mgmt) {
        mgmt.setTokenIssuanceTimestamp(applicationProperties.getTokenTTL());
        UUID newAccessToken = UUID.randomUUID();
        mgmt.setAccessToken(newAccessToken);

        OAuthTokenDto.OAuthTokenDtoBuilder oauthTokenResponseBuilder = OAuthTokenDto.builder()
                .accessToken(newAccessToken.toString())
                .expiresIn(applicationProperties.getTokenTTL());


        if (applicationProperties.isAllowTokenRefresh()) {
            if (mgmt.getRefreshToken() == null || applicationProperties.isAllowRefreshTokenRotation()) {
                var newRefreshToken = UUID.randomUUID();
                mgmt.setRefreshToken(newRefreshToken);
                oauthTokenResponseBuilder.refreshToken(newRefreshToken.toString());
            } else {
                oauthTokenResponseBuilder.refreshToken(mgmt.getRefreshToken().toString());
            }
        }
        credentialManagementRepository.save(mgmt);
        return oauthTokenResponseBuilder.build();
    }

    private CredentialOffer getCredentialOfferByPreAuthCode(String preAuthCode) {
        var uuid = uuidOrException(preAuthCode);
        var credentialOffer = credentialOfferRepository.findByPreAuthorizedCode(uuid);
        return getExpirationCheckedCredentialOffer(credentialOffer)
                .orElseThrow(() -> OAuthException.invalidGrant("Invalid preAuthCode"));
    }

    private Optional<CredentialManagement> getNonRevokedCredentialOffer(Optional<CredentialManagement> credentialOffer) {
        return credentialOffer.filter(offer -> offer.getCredentialManagementStatus() != CredentialStatusManagementType.REVOKED);
    }

    private Optional<CredentialOffer> getExpirationCheckedCredentialOffer(Optional<CredentialOffer> credentialOffer) {
        return credentialOffer
                .map(offer -> {
                    if (offer.getCredentialStatus() != CredentialOfferStatusType.EXPIRED
                            && offer.hasExpirationTimeStampPassed()) {
                        credentialStateMachine.sendEventAndUpdateStatus(offer, CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE);
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