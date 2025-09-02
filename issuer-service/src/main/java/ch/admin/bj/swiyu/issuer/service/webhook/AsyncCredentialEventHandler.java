package ch.admin.bj.swiyu.issuer.service.webhook;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@AllArgsConstructor
public class AsyncCredentialEventHandler {

    private final WebhookService webhookService;

    @EventListener
    @Async
    public void handleErrorEvent(ErrorEvent errorEvent) {
        webhookService.produceErrorEvent(errorEvent.credentialOfferId(), errorEvent.errorCode(), errorEvent.errorMessage());
        log.info("Processed ErrorEvent for CredentialOfferId: {}", errorEvent.credentialOfferId());
    }

    @EventListener
    @Async
    public void handleStateChangeEvent(StateChangeEvent stateChangeEvent) {
        webhookService.produceStateChangeEvent(stateChangeEvent.credentialOfferId(), stateChangeEvent.newState());
        log.info("Processed StateChangeEvent for CredentialOfferId: {}", stateChangeEvent.credentialOfferId());
    }

    @EventListener
    @Async
    public void handleDeferredEvent(DeferredEvent deferredEvent) {
        webhookService.produceDeferredEvent(deferredEvent.credentialOfferId(), deferredEvent.clientAgentInfo());
        log.info("Processed DeferredEvent for CredentialOfferId: {}", deferredEvent.credentialOfferId());
    }
}