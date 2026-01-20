package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.service.CredentialFormatFactory;
import ch.admin.bj.swiyu.issuer.service.EncryptionService;
import ch.admin.bj.swiyu.issuer.service.HolderBindingService;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachineConfig.CredentialManagementEvent.ISSUE;

/**
 * Builds credential envelopes and handles related state updates.
 */
@Slf4j
@Service
@AllArgsConstructor
public class CredentialEnvelopeService {

    private final CredentialFormatFactory vcFormatFactory;
    private final EncryptionService encryptionService;
    private final HolderBindingService holderBindingService;
    private final EventProducerService eventProducerService;
    private final CredentialRequestValidator credentialRequestValidator;
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
        credentialRequestValidator.validateCredentialRequest(credentialOffer, credentialRequest);

        CredentialManagement mgmt = credentialOffer.getCredentialManagement();

        List<ProofJwt> holderPublicKey;
        try {
            holderPublicKey = holderBindingService.getHolderPublicKey(credentialRequest, credentialOffer).stream().toList();
        } catch (Oid4vcException e) {
            eventProducerService.produceErrorEvent(e.getMessage(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, credentialOffer);
            throw e;
        }


        List<String> holderPublicKeyJwkList = holderPublicKey.stream()
                .map(ProofJwt::getBinding)
                .filter(Objects::nonNull)
                .toList();

        List<String> keyAttestationJwkList = holderPublicKey.stream()
                .map(ProofJwt::getAttestationJwt)
                .filter(Objects::nonNull)
                .toList();

        var vcBuilder = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(holderPublicKeyJwkList)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId());

        CredentialEnvelopeDto responseEnvelope;

        if (credentialOffer.isDeferredOffer()) {
            var transactionId = UUID.randomUUID();

            responseEnvelope = vcBuilder.buildDeferredCredential(transactionId);
            credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, CredentialStateMachineConfig.CredentialOfferEvent.DEFER);
            credentialOffer.initializeDeferredState(transactionId,
                    credentialRequest,
                    holderPublicKeyJwkList,
                    keyAttestationJwkList,
                    clientInfo,
                    applicationProperties);
            credentialOfferRepository.save(credentialOffer);
            eventProducerService.produceDeferredEvent(credentialOffer, clientInfo);
        } else {
            responseEnvelope = vcBuilder.buildCredentialEnvelope();
            credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
            credentialOfferRepository.save(credentialOffer);
            credentialStateMachine.sendEventAndUpdateStatus(mgmt, ISSUE);
            credentialManagementRepository.save(mgmt);
            eventProducerService.produceOfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());
        }

        return responseEnvelope;
    }

    /**
     * Builds and returns a credential envelope (OID4VCI 2.0).
     */
    public CredentialEnvelopeDto createCredentialEnvelopeDtoV2(CredentialOffer credentialOffer,
                                                               CredentialRequestClass credentialRequest,
                                                               ClientAgentInfo clientInfo,
                                                               CredentialManagement mgmt) {
        credentialRequestValidator.validateCredentialRequest(credentialOffer, credentialRequest);

        List<ProofJwt> holderJwkList;
        try {
            holderJwkList = holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer);
        } catch (Oid4vcException e) {
            eventProducerService.produceErrorEvent(e.getMessage(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, credentialOffer);
            throw e;
        }

        List<String> holderPublicKeyJwkList = holderJwkList.stream()
                .map(ProofJwt::getBinding)
                .filter(Objects::nonNull)
                .toList();

        var vcBuilder = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId()
                        .getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(encryptionService.issuerMetadataWithEncryptionOptions()
                        .getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .holderBindings(holderPublicKeyJwkList)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId());

        CredentialEnvelopeDto responseEnvelope;

        if (credentialOffer.isDeferredOffer()) {
            var transactionId = UUID.randomUUID();

            List<String> keyAttestationJwkList = holderJwkList.stream()
                    .map(ProofJwt::getAttestationJwt)
                    .filter(Objects::nonNull)
                    .toList();

            responseEnvelope = vcBuilder.buildDeferredCredentialV2(transactionId);
            credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, CredentialStateMachineConfig.CredentialOfferEvent.DEFER);
            credentialOffer.initializeDeferredState(transactionId,
                    credentialRequest,
                    holderPublicKeyJwkList,
                    keyAttestationJwkList,
                    clientInfo,
                    applicationProperties);
            credentialOfferRepository.save(credentialOffer);
            eventProducerService.produceDeferredEvent(credentialOffer, clientInfo);
        } else {
            responseEnvelope = vcBuilder.buildCredentialEnvelopeV2();
            credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
            credentialStateMachine.sendEventAndUpdateStatus(mgmt, ISSUE);
            credentialOfferRepository.save(credentialOffer);
            credentialManagementRepository.save(mgmt);
            eventProducerService.produceOfferStateChangeEvent(mgmt.getId(), credentialOffer.getId(), credentialOffer.getCredentialStatus());
        }

        return responseEnvelope;
    }
}

