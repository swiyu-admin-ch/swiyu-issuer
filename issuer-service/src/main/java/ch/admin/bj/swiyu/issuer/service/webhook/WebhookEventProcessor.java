package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.common.config.WebhookProperties;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventRepository;
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

/**
 * Service responsible for processing and sending webhook callback events to external systems.
 * Runs periodically to send pending events via HTTP POST requests.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebhookEventProcessor {
    private final WebhookProperties webhookProperties;
    private final CallbackEventRepository callbackEventRepository;
    private final RestClient restClient;

    /**
     * Periodically processes all pending callback events and sends them to the configured callback URI.
     * Events are deleted from the database after successful delivery.
     * Failed deliveries are retried on the next scheduled execution to guarantee at-least-once delivery.
     */
    @Scheduled(initialDelay = 0, fixedDelayString = "${webhook.callback-interval}")
    @Transactional
    public void triggerProcessCallback() {
        if (StringUtils.isBlank(webhookProperties.getCallbackUri())) {
            // No Callback URI defined; We do not need to do callbacks
            return;
        }
        
        var events = callbackEventRepository.findAll();
        if (!events.isEmpty()) {
            log.debug("Processing {} pending callback event(s)", events.size());
        }
        
        events.forEach(event -> processCallbackEvent(
                event, 
                webhookProperties.getCallbackUri(), 
                webhookProperties.getApiKeyHeader(), 
                webhookProperties.getApiKeyValue()
        ));
    }

    private void processCallbackEvent(CallbackEvent event, String callbackUri, String authHeader, String authValue) {
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
            log.info("Successfully sent callback event {} to {}", event.getId(), callbackUri);
        } catch (RestClientResponseException e) {
            // Note: If delivery failed we will keep retrying to send the message ad-infinitum.
            // This is intended behaviour as we have to guarantee an at-least-once delivery.
            log.error("Callback to {} failed with status code {} with message {}", 
                    callbackUri, e.getStatusCode(), e.getMessage());
        }
    }
}

