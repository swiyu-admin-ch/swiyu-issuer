package ch.admin.bj.swiyu.issuer.service.webhook;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@AllArgsConstructor
public class CredentialEventHandler {

    private final WebhookService webhookService;

    @EventListener
    @Async
    public void handleErrorEvent(ErrorEvent errorEvent) {
        try {
            webhookService.produceErrorEvent(errorEvent.credentialOfferId(), errorEvent.errorCode(), errorEvent.errorMessage());
            log.info("Processed ErrorEvent for CredentialOfferId: {}", errorEvent.credentialOfferId());
        } catch (Exception e) {
            log.error("Failed to process ErrorEvent for {} with: {}", errorEvent.credentialOfferId(), e.getMessage(), e);
        }
    }

    @EventListener
    @Async
    public void handleStateChangeEvent(StateChangeEvent stateChangeEvent) {
        try {
            webhookService.produceStateChangeEvent(stateChangeEvent.credentialOfferId(), stateChangeEvent.newState());
            log.info("Processed StateChangeEvent for CredentialOfferId: {}", stateChangeEvent.credentialOfferId());
        } catch (Exception e) {
            log.error("Failed to process StateChangeEvent {} with: {}", stateChangeEvent.credentialOfferId(), e.getMessage(), e);
        }
    }

    @EventListener
    @Async
    public void handleDeferredEvent(DeferredEvent deferredEvent) {
        try {
            webhookService.produceDeferredEvent(deferredEvent.credentialOfferId(), deferredEvent.clientAgentInfo());
            log.info("Processed DeferredEvent for CredentialOfferId: {}", deferredEvent.credentialOfferId());
        } catch (Exception e) {
            log.error("Failed to process DeferredEvent for {} with: {}", deferredEvent.credentialOfferId(), e.getMessage(), e);
        }
    }
}