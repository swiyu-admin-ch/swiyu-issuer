package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.WebhookProperties;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventRepository;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventTrigger;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.util.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.service.statusregistry.StatusResponseMapper.toCredentialStatusTypeDto;

/**
 * Service responsible for producing and persisting webhook callback events.
 * These events are later processed and sent to external systems by the WebhookEventProcessor.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebhookEventProducer {
    private final WebhookProperties webhookProperties;
    private final CallbackEventRepository callbackEventRepository;

    /**
     * Produces a state change event when a credential offer status changes.
     */
    @Transactional
    public void produceOfferStateChangeEvent(UUID credentialOfferId, CredentialOfferStatusType state) {
        createEvent(credentialOfferId, CallbackEventType.VC_STATUS_CHANGED, toCredentialStatusTypeDto(state).name(), null, CallbackEventTrigger.CREDENTIAL_OFFER);
    }

    /**
     * Produces a state change event when a credential status changes.
     */
    @Transactional
    public void produceManagementStateChangeEvent(UUID credentialOfferManagementId, CredentialStatusManagementType state) {
        createEvent(credentialOfferManagementId, CallbackEventType.VC_STATUS_CHANGED, toCredentialStatusTypeDto(state).name(), null, CallbackEventTrigger.CREDENTIAL_MANAGEMENT);
    }

    /**
     * Produces an error event when an error occurs during credential processing.
     */
    @Transactional
    public void produceErrorEvent(UUID credentialOfferId, CallbackErrorEventTypeDto errorCode, String errorMessage) {
        createEvent(credentialOfferId, CallbackEventType.ERROR, errorCode.name(), errorMessage, null);
    }

    /**
     * Produces a deferred event when a credential is deferred.
     */
    @Transactional
    public void produceDeferredEvent(UUID credentialOfferId, String clientAgentInfo) {
        var message = CredentialOfferStatusType.DEFERRED.getDisplayName();
        createEvent(credentialOfferId, CallbackEventType.VC_DEFERRED, message, clientAgentInfo, CallbackEventTrigger.CREDENTIAL_OFFER);
    }

    private void createEvent(UUID subjectId, CallbackEventType callbackEventType, String message, String description, CallbackEventTrigger trigger) {
        if (StringUtils.isBlank(webhookProperties.getCallbackUri())) {
            // No Callback URI defined; We can not do callbacks
            log.debug("Skipping callback event creation - no callback URI configured");
            return;
        }
        var event = CallbackEvent.builder()
                .subjectId(subjectId)
                .type(callbackEventType)
                .event(message)
                .timestamp(Instant.now())
                .eventDescription(description)
                .eventTrigger(trigger)
                .build();
        callbackEventRepository.save(event);
        log.debug("Created callback event for subject {} with type {}", subjectId, callbackEventType);
    }
}