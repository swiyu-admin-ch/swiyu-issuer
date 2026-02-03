package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredCredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.service.CredentialBuilder;
import ch.admin.bj.swiyu.issuer.service.CredentialFormatFactory;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import ch.admin.bj.swiyu.issuer.service.mapper.CredentialRequestMapper;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
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
    private final CredentialFormatFactory credentialFormatFactory;
    private final JweService jweService;
    private final OAuthService oAuthService;
    private final EventProducerService eventProducerService;
    private final CredentialStateMachine credentialStateMachine;

    /**
     * Issues a deferred credential using the OID4VCI 1.0 flow.
     *
     * @param deferredCredentialRequest request payload containing transaction and credential parameters
     * @param accessToken access token authorizing issuance for the transaction
     * @return envelope with the issued credential response
     * @throws Oid4vcException when validation fails (expired, cancelled, or not ready)
     * @throws OAuthException when the provided access token is invalid or expired
     */
    @Deprecated(since = "OID4VCI 1.0")
    public CredentialEnvelopeDto createCredentialFromDeferredRequest(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        CredentialOffer credentialOffer = getAndValidateCredentialOfferForDeferred(deferredCredentialRequest,
                accessToken);

        CredentialManagement mgmt = credentialOffer.getCredentialManagement();
        var credentialRequest = credentialOffer.getCredentialRequest();
        var credentialEnvelopeDto = buildEnvelopeV1(credentialOffer, credentialRequest);

        // Just to be aligned old but wrong implementation! Must be removed when ending of support of V1
        if(!isOfferReady(credentialOffer)){
            throw new Oid4vcException(ISSUANCE_PENDING, "The credential is not marked as ready to be issued");
        }

        markIssuanceCompleted(credentialOffer, mgmt);


        return credentialEnvelopeDto;
    }

    /**
     * Issues a deferred credential using the OID4VCI 2.0 flow.
     *
     * @param deferredCredentialRequest request payload containing transaction and credential parameters
     * @param accessToken access token authorizing issuance for the transaction
     * @return envelope with the issued credential response
     * @throws Oid4vcException when validation fails (expired, cancelled, or not ready)
     * @throws OAuthException when the provided access token is invalid or expired
     */
    public CredentialEnvelopeDto createCredentialFromDeferredRequestV2(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        CredentialOffer credentialOffer = getAndValidateCredentialOfferForDeferred(deferredCredentialRequest,
                accessToken);

        CredentialManagement credentialMgmt = credentialOffer.getCredentialManagement();
        var responseEncryption = Optional.ofNullable(deferredCredentialRequest.credentialResponseEncryption())
                .map(CredentialRequestMapper::toCredentialResponseEncryption)
                .orElse(credentialOffer.getCredentialRequest().getCredentialResponseEncryption());
        var credentialEnvelopeDto = buildEnvelopeV2(credentialOffer, responseEncryption);

        // Only mark issuance completed if the offer is READY (do nothing if still in DEFERRED)
        if (isOfferReady(credentialOffer)) {
            markIssuanceCompleted(credentialOffer, credentialMgmt);
        }

        return credentialEnvelopeDto;
    }

    // Helper methods are package-private to allow focused unit testing.
    CredentialEnvelopeDto buildEnvelopeV1(CredentialOffer credentialOffer, CredentialRequestClass credentialRequest) {
        var credentialSupportedId = getMetadataCredentialSupportedId(credentialOffer);
        return credentialFormatFactory
                .getFormatBuilder(credentialSupportedId)
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(credentialOffer.getHolderJWKs())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();
    }

    /**
     * Builds a credential envelope for OID4VCI 2.0 requests.
     */
    CredentialEnvelopeDto buildEnvelopeV2(CredentialOffer credentialOffer, CredentialResponseEncryptionClass responseEncryption) {
        var credentialSupportedId = getMetadataCredentialSupportedId(credentialOffer);
        CredentialBuilder credentialBuilder = credentialFormatFactory
                .getFormatBuilder(credentialSupportedId)
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(
                        jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(),
                        responseEncryption)
                .holderBindings(credentialOffer.getHolderJWKs())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId());
        // Depending on the offer status, build either a ready credential or a deferred one
        if (isOfferReady(credentialOffer)) {
            return credentialBuilder
                    .buildCredentialEnvelopeV2();
        } else {
            var transactionId = UUID.randomUUID();
            return credentialBuilder
                    .buildDeferredCredentialV2(transactionId);
        }
    }

    /**
     * Extracts and validates the first metadata_credential_supported_id entry.
     *
     * @throws Oid4vcException when missing or empty
     */
    String getMetadataCredentialSupportedId(CredentialOffer credentialOffer) {
        var metadataIds = credentialOffer.getMetadataCredentialSupportedId();
        if (metadataIds == null || metadataIds.isEmpty()) {
            throw new Oid4vcException(CREDENTIAL_REQUEST_DENIED, "Missing metadata_credential_supported_id for deferred issuance");
        }
        return metadataIds.getFirst();
    }

    /**
     * Advances state, persists entities, and emits offer state change events after issuance.
     */
    void markIssuanceCompleted(CredentialOffer credentialOffer, CredentialManagement mgmt) {
        credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        credentialStateMachine.sendEventAndUpdateStatus(mgmt, ISSUE);

        credentialOfferRepository.save(credentialOffer);
        credentialManagementRepository.save(mgmt);
    }

    /**
     * Resolves the credential offer for a deferred transaction and runs validation checks.
     */
    CredentialOffer getAndValidateCredentialOfferForDeferred(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {

        CredentialOffer credentialOffer = getCredentialOfferByTransactionIdAndAccessToken(
                deferredCredentialRequest.transactionId(),
                accessToken);

        CredentialManagement mgmt = credentialOffer.getCredentialManagement();

        validateOfferProcessable(credentialOffer);
        isOfferReady(credentialOffer);
        validateTokenNotExpired(credentialOffer, mgmt);

        // Only validate presence of credential request when the offer is READY (i.e., not DEFERRED)
        if (isOfferReady(credentialOffer)) {
            validateCredentialRequestPresent(credentialOffer);
        }

        return credentialOffer;
    }

    /**
     * Ensures the offer is still processable (not cancelled/expired).
     */
    void validateOfferProcessable(CredentialOffer credentialOffer) {
        if (!credentialOffer.isProcessableOffer()) {
            throw new Oid4vcException(CREDENTIAL_REQUEST_DENIED,
                    "The credential can not be issued anymore, the offer was either cancelled or expired");
        }
    }

    /**
     * Ensures the offer is marked READY before issuing.
     */
    boolean isOfferReady(CredentialOffer credentialOffer) {
        if (credentialOffer.getCredentialStatus() == CredentialOfferStatusType.READY) {
            return true;
        }
        return false;
    }

    /**
     * Ensures the access token associated to the management entry is still valid; emits error events when expired.
     */
    void validateTokenNotExpired(CredentialOffer credentialOffer, CredentialManagement mgmt) {
        if (mgmt.hasTokenExpirationPassed()) {
            log.info("Received AccessToken for deferred credential offer {} was expired.", credentialOffer.getId());

            eventProducerService.produceErrorEvent("AccessToken expired, offer is stuck in READY",
                    CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED,
                    credentialOffer);

            throw OAuthException.invalidRequest("AccessToken expired.");
        }
    }

    /**
     * Ensures the credential request payload exists on the offer.
     */
    void validateCredentialRequestPresent(CredentialOffer credentialOffer) {
        if (credentialOffer.getCredentialRequest() == null) {
            throw new IllegalArgumentException("Credential Request is missing");
        }
    }

    /**
     * Looks up an offer by transaction ID constrained to the provided access token.
     *
     * @throws Oid4vcException when the transaction ID cannot be resolved within the token scope
     */
    private CredentialOffer getCredentialOfferByTransactionIdAndAccessToken(UUID transactionId, String accessToken) {
        CredentialManagement mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        var offers = mgmt.getCredentialOffers();

        return offers.stream().filter(o -> o.getTransactionId() != null
                        && o.getTransactionId().equals(transactionId))
                .findFirst()
                .orElseThrow(() -> new Oid4vcException(INVALID_TRANSACTION_ID, "Invalid transactional id"));
    }
}
