package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
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
                credentialOffer.getId()
        );
        applicationEventPublisher.publishEvent(errorEvent);
    }

    public void produceStateChangeEvent(UUID credentialOfferId, CredentialStatusType state) {
        var stateChangeEvent = new StateChangeEvent(
                credentialOfferId,
                state
        );
        applicationEventPublisher.publishEvent(stateChangeEvent);
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
