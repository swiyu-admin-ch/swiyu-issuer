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

    private final WebhookEventProducer webhookEventProducer;

    @EventListener
    @Async
    public void handleErrorEvent(ErrorEvent errorEvent) {
        webhookEventProducer.produceErrorEvent(errorEvent.credentialOfferId(), errorEvent.errorCode(), errorEvent.errorMessage());
        log.info("Processed ErrorEvent for CredentialOfferId: {}", errorEvent.credentialOfferId());
    }

    @EventListener
    @Async
    public void handleOfferStateChangeEvent(OfferStateChangeEvent stateChangeEvent) {
        webhookEventProducer.produceOfferStateChangeEvent(stateChangeEvent.credentialOfferId(), stateChangeEvent.newState());
        log.info("Processed StateChangeEvent for CredentialOfferId: {}", stateChangeEvent.credentialOfferId());
    }

    @EventListener
    @Async
    public void handleManagementStateChangeEvent(StateChangeEvent stateChangeEvent) {
        webhookEventProducer.produceManagementStateChangeEvent(stateChangeEvent.credentialOfferId(), stateChangeEvent.newState());
        log.info("Processed StateChangeEvent for CredentialOfferId: {}", stateChangeEvent.credentialOfferId());
    }

    @EventListener
    @Async
    public void handleDeferredEvent(DeferredEvent deferredEvent) {
        webhookEventProducer.produceDeferredEvent(deferredEvent.credentialOfferId(), deferredEvent.clientAgentInfo());
        log.info("Processed DeferredEvent for CredentialOfferId: {}", deferredEvent.credentialOfferId());
    }
}