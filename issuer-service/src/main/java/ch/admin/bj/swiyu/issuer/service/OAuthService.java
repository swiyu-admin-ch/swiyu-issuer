package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
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

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_TRANSACTION_ID;
import static java.util.Objects.isNull;

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
        offer.setTokenIssuanceTimestamp(applicationProperties.getTokenTTL());

        credentialOfferRepository.save(offer);
        eventProducerService.produceStateChangeEvent(offer.getId(), offer.getCredentialStatus());

        return OAuthTokenDto.builder()
                .accessToken(offer.getAccessToken()
                        .toString())
                .expiresIn(applicationProperties.getTokenTTL())
                .cNonce(offer.getNonce()
                        .toString())
                .build();
    }

    @Transactional
    public CredentialOffer getCredentialOfferByAccessToken(String accessToken) {
        var uuid = uuidOrException(accessToken);
        return getNonExpiredCredentialOffer(credentialOfferRepository.findByAccessToken(uuid))
                .orElseThrow(() -> OAuthException.invalidToken("Invalid accessToken"));
    }

    private CredentialOffer getCredentialOfferByPreAuthCode(String preAuthCode) {
        var uuid = uuidOrException(preAuthCode);
        return getNonExpiredCredentialOffer(credentialOfferRepository.findByPreAuthorizedCode(uuid))
                .orElseThrow(() -> OAuthException.invalidGrant("Invalid preAuthCode"));
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
