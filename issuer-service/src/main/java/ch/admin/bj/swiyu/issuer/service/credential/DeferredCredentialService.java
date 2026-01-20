package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredCredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.CredentialFormatFactory;
import ch.admin.bj.swiyu.issuer.service.EncryptionService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.*;
import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachineConfig.CredentialManagementEvent.ISSUE;

/**
 * Handles deferred credential issuance flows.
 */
@Slf4j
@Service
@AllArgsConstructor
public class DeferredCredentialService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialManagementRepository credentialManagementRepository;
    private final CredentialFormatFactory vcFormatFactory;
    private final EncryptionService encryptionService;
    private final OAuthService oAuthService;
    private final EventProducerService eventProducerService;
    private final CredentialStateMachine credentialStateMachine;

    /**
     * Issues a deferred credential (OID4VCI 1.0).
     */
    @Deprecated(since = "OID4VCI 1.0")
    public CredentialEnvelopeDto createCredentialFromDeferredRequest(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        CredentialOffer credentialOffer = getAndValidateCredentialOfferForDeferred(deferredCredentialRequest,
                accessToken);

        CredentialManagement mgmt = credentialOffer.getCredentialManagement();

        var credentialRequest = credentialOffer.getCredentialRequest();

        CredentialEnvelopeDto vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(credentialOffer.getHolderJWKs())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        credentialStateMachine.sendEventAndUpdateStatus(mgmt, ISSUE);

        credentialOfferRepository.save(credentialOffer);
        credentialManagementRepository.save(mgmt);

        eventProducerService.produceOfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());

        return vc;
    }

    /**
     * Issues a deferred credential (OID4VCI 2.0).
     */
    public CredentialEnvelopeDto createCredentialFromDeferredRequestV2(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        CredentialOffer credentialOffer = getAndValidateCredentialOfferForDeferred(deferredCredentialRequest,
                accessToken);

        CredentialManagement credentialMgmt = credentialOffer.getCredentialManagement();

        var credentialRequest = credentialOffer.getCredentialRequest();

        CredentialEnvelopeDto vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(credentialOffer.getHolderJWKs())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelopeV2();

        credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        credentialStateMachine.sendEventAndUpdateStatus(credentialMgmt, ISSUE);

        credentialOfferRepository.save(credentialOffer);
        credentialManagementRepository.save(credentialMgmt);

        eventProducerService.produceOfferStateChangeEvent(credentialMgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());

        return vc;
    }

    private CredentialOffer getAndValidateCredentialOfferForDeferred(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        CredentialOffer credentialOffer = getCredentialOfferByTransactionIdAndAccessToken(
                deferredCredentialRequest.transactionId(),
                accessToken);

        CredentialManagement mgmt = credentialOffer.getCredentialManagement();

        if (!credentialOffer.isProcessableOffer()) {
            throw new Oid4vcException(CREDENTIAL_REQUEST_DENIED,
                    "The credential can not be issued anymore, the offer was either cancelled or expired");
        }

        if (credentialOffer.getCredentialStatus() != CredentialOfferStatusType.READY) {
            throw new Oid4vcException(ISSUANCE_PENDING, "The credential is not marked as ready to be issued");
        }

        if (mgmt.hasTokenExpirationPassed()) {
            log.info("Received AccessToken for deferred credential offer {} was expired.", credentialOffer.getId());

            eventProducerService.produceErrorEvent("AccessToken expired, offer is stuck in READY",
                    CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED,
                    credentialOffer);

            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        if (credentialOffer.getCredentialRequest() == null) {
            throw new IllegalArgumentException("Credential Request is missing");
        }

        return credentialOffer;
    }

    private CredentialOffer getCredentialOfferByTransactionIdAndAccessToken(UUID transactionId, String accessToken) {
        CredentialManagement mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        var offers = mgmt.getCredentialOffers();

        return offers.stream().filter(o -> o.getTransactionId() != null
                        && o.getTransactionId().equals(transactionId))
                .findFirst()
                .orElseThrow(() -> new Oid4vcException(INVALID_TRANSACTION_ID, "Invalid transactional id"));
    }
}

