package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.CredentialBuilder;
import ch.admin.bj.swiyu.issuer.service.CredentialFormatFactory;
import ch.admin.bj.swiyu.issuer.service.EncryptionService;
import ch.admin.bj.swiyu.issuer.service.HolderBindingService;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;

import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachineConfig.CredentialManagementEvent.ISSUE;

/**
 * Builds credential envelopes and drives the surrounding state transitions and events for both OID4VCI versions.
 * <p>
 * The service centralises common steps (validation, holder binding, VC builder creation, deferred vs. immediate flows)
 * and uses functional parameters ({@link java.util.function.Supplier} and {@link java.util.function.Function}) to
 * inject the version-specific build operations for immediate and deferred credentials.
 */
@Slf4j
@Service
@AllArgsConstructor
public class CredentialEnvelopeService {

    private final CredentialFormatFactory credentialFormatFactory;
    private final EncryptionService encryptionService;
    private final HolderBindingService holderBindingService;
    private final EventProducerService eventProducerService;
    private final IssuerMetadata issuerMetadata;
    private final CredentialStateMachine credentialStateMachine;
    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialManagementRepository credentialManagementRepository;
    private final ApplicationProperties applicationProperties;

    /**
     * Builds and returns a credential envelope (OID4VCI 1.0).
     */
    @Deprecated(since = "OID4VCI 1.0")
    public CredentialEnvelopeDto createCredentialEnvelopeDto(CredentialOffer credentialOffer,
                                                             CredentialRequestClass credentialRequest,
                                                             ClientAgentInfo clientInfo) {
        var context = buildContext(credentialOffer, credentialRequest, clientInfo, credentialOffer.getCredentialManagement());
        var holderKeys = loadHolderKeysV1(context);
        var vcBuilder = buildVcBuilder(context.offer(), context.request(), holderKeys.bindings());

        return issueCredential(context,
                holderKeys,
                vcBuilder::buildCredentialEnvelope,
                vcBuilder::buildDeferredCredential);
    }

    /**
     * Builds and returns a credential envelope (OID4VCI 2.0).
     */
    public CredentialEnvelopeDto createCredentialEnvelopeDtoV2(CredentialOffer credentialOffer,
                                                               CredentialRequestClass credentialRequest,
                                                               ClientAgentInfo clientInfo,
                                                               CredentialManagement mgmt) {
        var context = buildContext(credentialOffer, credentialRequest, clientInfo, mgmt);
        var holderKeys = loadHolderKeysV2(context);
        var vcBuilder = buildVcBuilder(context.offer(), context.request(), holderKeys.bindings());

        return issueCredential(context,
                holderKeys,
                vcBuilder::buildCredentialEnvelopeV2,
                vcBuilder::buildDeferredCredentialV2);
    }

    /**
     * Resolve metadata, perform token-expiry check, and validate the incoming request against the offer.
     */
    private EnvelopeContext buildContext(CredentialOffer credentialOffer,
                                         CredentialRequestClass credentialRequest,
                                         ClientAgentInfo clientInfo,
                                         CredentialManagement mgmt) {
         if (mgmt.hasTokenExpirationPassed()) {
             handleExpiredToken(credentialOffer);
         }

        CredentialRequestValidator.validateCredentialRequest(credentialOffer,
                credentialRequest,
                issuerMetadata.getCredentialConfigurationById(credentialOffer.getMetadataCredentialSupportedId().getFirst()));

        return new EnvelopeContext(credentialOffer, mgmt, credentialRequest, clientInfo);
    }

    /**
     * Load and validate holder binding keys for OID4VCI 1.0, publishing errors on failure.
     */
    private HolderKeys loadHolderKeysV1(EnvelopeContext context) {
        List<ProofJwt> holderPublicKey;
        try {
            holderPublicKey = holderBindingService.getHolderPublicKey(context.request(), context.offer()).stream().toList();
        } catch (Oid4vcException e) {
            eventProducerService.produceErrorEvent(e.getMessage(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, context.offer());
            throw e;
        }

        return new HolderKeys(toBindings(holderPublicKey), toAttestations(holderPublicKey));
    }

    /**
     * Load and validate holder binding keys for OID4VCI 2.0, publishing errors on failure.
     */
    private HolderKeys loadHolderKeysV2(EnvelopeContext context) {
        List<ProofJwt> holderJwkList;
        try {
            holderJwkList = holderBindingService.getValidateHolderPublicKeys(context.request(), context.offer());
        } catch (Oid4vcException e) {
            eventProducerService.produceErrorEvent(e.getMessage(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, context.offer());
            throw e;
        }

        return new HolderKeys(toBindings(holderJwkList), toAttestations(holderJwkList));
    }

    private List<String> toBindings(List<ProofJwt> proofJwts) {
        return proofJwts.stream()
                .map(ProofJwt::getBinding)
                .filter(Objects::nonNull)
                .toList();
    }

    private List<String> toAttestations(List<ProofJwt> proofJwts) {
        return proofJwts.stream()
                .map(ProofJwt::getAttestationJwt)
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Issues the credential and updates state. Uses a {@link Supplier} for the immediate build path and a
     * {@link Function} (UUID transactionId -> CredentialEnvelopeDto) for the deferred path so that version-specific
     * builder methods can be passed in without duplicating control flow.
     */
    private CredentialEnvelopeDto issueCredential(EnvelopeContext context,
                                                  HolderKeys holderKeys,
                                                  Supplier<CredentialEnvelopeDto> buildImmediate,
                                                  Function<UUID, CredentialEnvelopeDto> buildDeferred) {
        if (context.offer().isDeferredOffer()) {
            var transactionId = UUID.randomUUID();
            var responseEnvelope = buildDeferred.apply(transactionId);

            credentialStateMachine.sendEventAndUpdateStatus(context.offer(), CredentialStateMachineConfig.CredentialOfferEvent.DEFER);
            context.offer().initializeDeferredState(transactionId,
                    context.request(),
                    holderKeys.bindings(),
                    holderKeys.attestations(),
                    context.clientInfo(),
                    applicationProperties);
            credentialOfferRepository.save(context.offer());
            eventProducerService.produceDeferredEvent(context.offer(), context.clientInfo());
            return responseEnvelope;
        }

        var responseEnvelope = buildImmediate.get();
        credentialStateMachine.sendEventAndUpdateStatus(context.offer(), CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        credentialStateMachine.sendEventAndUpdateStatus(context.mgmt(), ISSUE);
        credentialOfferRepository.save(context.offer());
        credentialManagementRepository.save(context.mgmt());
        eventProducerService.produceOfferStateChangeEvent(context.mgmt().getId(), context.offer().getId(), context.offer().getCredentialStatus());
        return responseEnvelope;
    }

    /**
     * Prepare a version-agnostic credential builder with common parameters; specific build methods are supplied later.
     */
    private CredentialBuilder buildVcBuilder(CredentialOffer credentialOffer,
                                             CredentialRequestClass credentialRequest,
                                             List<String> holderBindings) {
        return credentialFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(holderBindings)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId());
    }

    private record EnvelopeContext(CredentialOffer offer,
                                   CredentialManagement mgmt,
                                   CredentialRequestClass request,
                                   ClientAgentInfo clientInfo) {
    }

    private record HolderKeys(List<String> bindings, List<String> attestations) {
    }

    private void handleExpiredToken(CredentialOffer credentialOffer) {
        log.info("Received AccessToken for credential offer {} was expired.", credentialOffer.getId());
        eventProducerService.produceErrorEvent("AccessToken expired, offer possibly stuck in IN_PROGRESS",
                CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED,
                credentialOffer);

        throw OAuthException.invalidRequest("AccessToken expired.");
    }
}
