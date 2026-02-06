package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.UNSUPPORTED_CREDENTIAL_FORMAT;
import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.UNSUPPORTED_CREDENTIAL_TYPE;

/**
 * Stateless validation helpers for credential requests compared to an offer and issuer configuration.
 */
@Slf4j
@UtilityClass
public class CredentialRequestValidator {

    /**
     * Validate offer state, format and configuration alignment for a credential request.
     *
     * @param credentialOffer     the offer against which the request is validated
     * @param credentialRequest   the incoming credential request
     * @param credentialConfiguration configuration referenced by the offer
     */
    public void validateCredentialRequest(CredentialOffer credentialOffer,
                                          CredentialRequestClass credentialRequest,
                                          CredentialConfiguration credentialConfiguration) {
        validateOfferState(credentialOffer);
        validateFormat(credentialRequest, credentialConfiguration);
        validateConfigurationId(credentialOffer, credentialRequest);
    }

    private void validateOfferState(CredentialOffer credentialOffer) {
        if (!credentialOffer.getCredentialStatus().equals(CredentialOfferStatusType.IN_PROGRESS)
                && !credentialOffer.getCredentialStatus().equals(CredentialOfferStatusType.REQUESTED)) {
            log.info("Credential offer {} failed to create VC, as state was not IN_PROGRESS instead was {}",
                    credentialOffer.getId(), credentialOffer.getCredentialStatus());
            throw OAuthException.invalidGrant(String.format(
                    "Offer is not valid anymore. The current offer state is %s." +
                            "The user should probably contact the business issuer about this.",
                    credentialOffer.getCredentialStatus()));
        }
    }

    private void validateFormat(CredentialRequestClass credentialRequest,
                                CredentialConfiguration credentialConfiguration) {
        if (!credentialConfiguration.getFormat().equals(credentialRequest.getFormat())) {
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_FORMAT, "Mismatch between requested and offered format.");
        }
    }

    private void validateConfigurationId(CredentialOffer credentialOffer,
                                         CredentialRequestClass credentialRequest) {
        if (credentialRequest.getCredentialConfigurationId() != null
                && !credentialOffer.getMetadataCredentialSupportedId()
                .getFirst()
                .equals(credentialRequest.getCredentialConfigurationId())) {
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_TYPE,
                    "Mismatch between requested and offered credential configuration id.");
        }
    }
}
