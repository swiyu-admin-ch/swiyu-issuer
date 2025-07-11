package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.WebhookProperties;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventRepository;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.service.mapper.CallbackMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.util.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.time.Instant;
import java.util.UUID;

/**
 * Service collecting functions for the Webhook functionality.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebhookService {
    private final WebhookProperties webhookProperties;
    private final CallbackEventRepository callbackEventRepository;
    private final RestClient restClient;

    @Transactional
    public void produceStateChangeEvent(UUID credentialOfferId, CredentialStatusType state) {
        createEvent(credentialOfferId, CallbackEventType.VC_STATUS_CHANGED, state.getDisplayName(), null);
    }

    @Transactional
    public void produceErrorEvent(UUID credentialOfferId, CallbackErrorEventTypeDto errorCode, String errorMessage) {
        createEvent(credentialOfferId, CallbackEventType.ERROR, errorCode.name(), errorMessage);
    }

    @Transactional
    public void produceDeferredEvent(UUID credentialOfferId, CredentialStatusType state, String clientAgentInfo) {

        createEvent(credentialOfferId, CallbackEventType.VC_DEFERRED, state.getDisplayName(), clientAgentInfo);
    }

    private void createEvent(UUID subjectId, CallbackEventType callbackEventType, String message, String description) {
        if (StringUtils.isBlank(webhookProperties.getCallbackUri())) {
            // No Callback URI defined; We can not do callbacks
            return;
        }
        var event = CallbackEvent.builder()
                .subjectId(subjectId)
                .type(callbackEventType)
                .event(message)
                .timestamp(Instant.now())
                .eventDescription(description)
                .build();
        callbackEventRepository.save(event);
    }

    @Scheduled(initialDelay = 0, fixedDelayString = "${webhook.callback-interval}")
    @Transactional
    public void triggerProcessCallback() {
        if (StringUtils.isBlank(webhookProperties.getCallbackUri())) {
            // No Callback URI defined; We do not need to do callbacks
            return;
        }
        var events = callbackEventRepository.findAll();
        events.forEach(event -> processCallbackEvent(event, webhookProperties.getCallbackUri(), webhookProperties.getApiKeyHeader(), webhookProperties.getApiKeyValue()));
    }

    private void processCallbackEvent(CallbackEvent event, String callbackUri, String authHeader, String authValue) {
        // Send the event
        var request = restClient.post()
                .uri(callbackUri);
        if (!StringUtils.isBlank(authHeader)) {
            request = request.header(authHeader, authValue);
        }
        try {
            request
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(CallbackMapper.toWebhookCallbackDto(event))
                    .retrieve()
                    .toBodilessEntity();
            callbackEventRepository.delete(event);
        } catch (RestClientResponseException e) {
            // Note; If delivery failed we will keep retrying to send the message ad-infinitum.
            // This is intended behaviour as we have to guarantee an at-least-once delivery.
            log.error("Callback to {} failed with status code {} with message {}", webhookProperties.getCallbackUri(), e.getStatusCode(), e.getMessage());
        }
    }

}