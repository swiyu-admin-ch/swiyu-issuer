package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.UNSUPPORTED_CREDENTIAL_FORMAT;
import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.UNSUPPORTED_CREDENTIAL_TYPE;

/**
 * Validates credential requests against offers and issuer metadata.
 */
@Slf4j
@Service
@AllArgsConstructor
public class CredentialRequestValidator {

    private final IssuerMetadata issuerMetadata;
    private final EventProducerService eventProducerService;

    /**
     * Validates request format, type, status, and token validity.
     */
    public void validateCredentialRequest(CredentialOffer credentialOffer,
                                          CredentialRequestClass credentialRequest) {
        CredentialManagement mgmt = credentialOffer.getCredentialManagement();

        if (!credentialOffer.getCredentialStatus().equals(CredentialOfferStatusType.IN_PROGRESS)
                && !credentialOffer.getCredentialStatus().equals(CredentialOfferStatusType.REQUESTED)) {
            log.info("Credential offer {} failed to create VC, as state was not IN_PROGRESS instead was {}",
                    credentialOffer.getId(), credentialOffer.getCredentialStatus());
            throw OAuthException.invalidGrant(String.format(
                    "Offer is not valid anymore. The current offer state is %s." +
                            "The user should probably contact the business issuer about this.",
                    credentialOffer.getCredentialStatus()));
        }

        if (mgmt.hasTokenExpirationPassed()) {
            log.info("Received AccessToken for credential offer {} was expired.", credentialOffer.getId());
            eventProducerService.produceErrorEvent("AccessToken expired, offer possibly stuck in IN_PROGRESS",
                    CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED,
                    credentialOffer);

            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        if (!credentialConfiguration.getFormat().equals(credentialRequest.getFormat())) {
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_FORMAT, "Mismatch between requested and offered format.");
        }

        if (credentialRequest.getCredentialConfigurationId() != null
                && !credentialOffer.getMetadataCredentialSupportedId()
                .getFirst()
                .equals(credentialRequest.getCredentialConfigurationId())) {
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_TYPE,
                    "Mismatch between requested and offered credential configuration id.");
        }
    }
}

