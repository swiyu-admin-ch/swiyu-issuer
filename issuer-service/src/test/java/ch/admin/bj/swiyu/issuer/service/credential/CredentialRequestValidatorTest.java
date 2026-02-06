package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.UNSUPPORTED_CREDENTIAL_FORMAT;
import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.UNSUPPORTED_CREDENTIAL_TYPE;
import static ch.admin.bj.swiyu.issuer.common.exception.OAuthError.INVALID_GRANT;
import static org.junit.jupiter.api.Assertions.*;

class CredentialRequestValidatorTest {

    @Test
    void validateCredentialRequest_happyPath() {
        CredentialOffer offer = offer(CredentialOfferStatusType.IN_PROGRESS);
        CredentialConfiguration configuration = configuration("dc+sd-jwt");
        CredentialRequestClass request = request("dc+sd-jwt", offer.getMetadataCredentialSupportedId().getFirst());

        assertDoesNotThrow(() -> CredentialRequestValidator.validateCredentialRequest(offer, request, configuration));
    }

    @Test
    void validateCredentialRequest_rejectsInvalidState() {
        CredentialOffer offer = offer(CredentialOfferStatusType.DEFERRED);
        CredentialConfiguration configuration = configuration("dc+sd-jwt");
        CredentialRequestClass request = request("dc+sd-jwt", offer.getMetadataCredentialSupportedId().getFirst());

        OAuthException ex = assertThrows(OAuthException.class,
                () -> CredentialRequestValidator.validateCredentialRequest(offer, request, configuration));
        assertEquals(INVALID_GRANT, ex.getError());
    }

    @Test
    void validateCredentialRequest_rejectsFormatMismatch() {
        CredentialOffer offer = offer(CredentialOfferStatusType.IN_PROGRESS);
        CredentialConfiguration configuration = configuration("vc+sd-jwt");
        CredentialRequestClass request = request("dc+sd-jwt", offer.getMetadataCredentialSupportedId().getFirst());

        Oid4vcException ex = assertThrows(Oid4vcException.class,
                () -> CredentialRequestValidator.validateCredentialRequest(offer, request, configuration));
        assertEquals(UNSUPPORTED_CREDENTIAL_FORMAT, ex.getError());
    }

    @Test
    void validateCredentialRequest_rejectsConfigurationIdMismatch() {
        CredentialOffer offer = offer(CredentialOfferStatusType.IN_PROGRESS);
        CredentialConfiguration configuration = configuration("dc+sd-jwt");
        CredentialRequestClass request = request("dc+sd-jwt", "other-config-id");

        Oid4vcException ex = assertThrows(Oid4vcException.class,
                () -> CredentialRequestValidator.validateCredentialRequest(offer, request, configuration));
        assertEquals(UNSUPPORTED_CREDENTIAL_TYPE, ex.getError());
    }

    private CredentialOffer offer(CredentialOfferStatusType status) {
        return CredentialOffer.builder()
                .credentialStatus(status)
                .metadataCredentialSupportedId(List.of("config-id"))
                .build();
    }

    private CredentialConfiguration configuration(String format) {
        CredentialConfiguration configuration = new CredentialConfiguration();
        configuration.setFormat(format);
        return configuration;
    }

    private CredentialRequestClass request(String format, String credentialConfigurationId) {
        CredentialRequestClass request = new CredentialRequestClass();
        request.setFormat(format);
        request.setCredentialConfigurationId(credentialConfigurationId);
        return request;
    }
}
