package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventTrigger;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.dto.callback.CallbackErrorEventTypeDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Create System events to be processed asynchronously
 */
@RequiredArgsConstructor
@Service
public class EventProducerService {
    private final ApplicationEventPublisher applicationEventPublisher;
    private final ObjectMapper objectMapper;

    public void produceErrorEvent(String errorMessage,
                                  CallbackErrorEventTypeDto oauthTokenExpired,
                                  CredentialOffer credentialOffer) {
        var errorEvent = new ErrorEvent(
                errorMessage,
                oauthTokenExpired,
                credentialOffer.getId(),
                CallbackEventTrigger.CREDENTIAL_OFFER
        );
        applicationEventPublisher.publishEvent(errorEvent);
    }

    /**
     * Publishes a management state change event for a credential management state transition.
     * Only used for Credential Management State Changes from CredentialStateMachineAction.
     *
     * @param credentialManagementId the id of the credential management entity
     * @param state                  the new target state
     */
    public void produceManagementStateChangeEvent(UUID credentialManagementId, CredentialStatusManagementType state) {
        var managementStateChangeEvent = new ManagementStateChangeEvent(
                credentialManagementId,
                state
        );
        applicationEventPublisher.publishEvent(managementStateChangeEvent);
    }

    /**
     * Publishes an offer state change event for a credential offer state transition.
     * Only used for Credential Offer State Changes from CredentialStateMachineAction.
     *
     * @param credentialOfferId the id of the credential offer
     * @param state             the new target state
     */
    public void produceOfferStateChangeEvent(UUID credentialOfferId, CredentialOfferStatusType state) {
        var offerStateChangeEvent = new OfferStateChangeEvent(
                credentialOfferId,
                state
        );
        applicationEventPublisher.publishEvent(offerStateChangeEvent);
    }

    public void produceDeferredEvent(CredentialOffer credentialOffer, ClientAgentInfo clientInfo) {
        try {
            var clientInfoString = objectMapper.writeValueAsString(clientInfo);
            var deferredEvent = new DeferredEvent(
                    credentialOffer.getId(),
                    clientInfoString
            );
            applicationEventPublisher.publishEvent(deferredEvent);

        } catch (JsonProcessingException e) {
            throw new JsonException("Error processing client info for deferred credential offer", e);
        }
    }
}