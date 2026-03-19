package ch.admin.bj.swiyu.issuer.service.webhook;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventTrigger;
import ch.admin.bj.swiyu.issuer.dto.callback.CallbackErrorEventTypeDto;

@Component
@Slf4j
@AllArgsConstructor
public class AsyncCredentialEventHandler {

    private final WebhookEventProducer webhookEventProducer;

    @EventListener
    @Async
    public void handleErrorEvent(ErrorEvent errorEvent) {
        webhookEventProducer.produceErrorEvent(errorEvent.credentialOfferId(), errorEvent.errorCode(), errorEvent.errorMessage(), errorEvent.trigger());
        log.info("Processed ErrorEvent for CredentialOfferId: {}", errorEvent.credentialOfferId());
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    @Async
    public void handleOfferStateChangeEvent(OfferStateChangeEvent stateChangeEvent) {
        webhookEventProducer.produceOfferStateChangeEvent(stateChangeEvent.credentialOfferId(), stateChangeEvent.newState());
        log.info("Processed StateChangeEvent for CredentialOfferId: {}", stateChangeEvent.credentialOfferId());
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    @Async
    public void handleOfferStateChangeRollback(OfferStateChangeEvent stateChangeEvent) {
        log.warn("Transaction rolled back for CredentialOfferId: {} – attempted state: {}. Sending error event.",
                stateChangeEvent.credentialOfferId(), stateChangeEvent.newState());
        webhookEventProducer.produceErrorEvent(stateChangeEvent.credentialOfferId(), CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED,
                "Status list update failed for state transition to " + stateChangeEvent.newState(), CallbackEventTrigger.CREDENTIAL_OFFER);
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    @Async
    public void handleManagementStateChangeEvent(ManagementStateChangeEvent managementStateChangeEvent) {
        webhookEventProducer.produceManagementStateChangeEvent(managementStateChangeEvent.credentialManagementId(), managementStateChangeEvent.newState());
        log.info("Processed StateChangeEvent for CredentialManagementId: {}", managementStateChangeEvent.credentialManagementId());
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    @Async
    public void handleManagementStateChangeRollback(ManagementStateChangeEvent managementStateChangeEvent) {
        log.warn("Transaction rolled back for CredentialManagementId: {} – attempted state: {}. Sending error event.",
                managementStateChangeEvent.credentialManagementId(), managementStateChangeEvent.newState());
        webhookEventProducer.produceErrorEvent(managementStateChangeEvent.credentialManagementId(), CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED,
                "Status list update failed for state transition to " + managementStateChangeEvent.newState(), CallbackEventTrigger.CREDENTIAL_MANAGEMENT);
    }

    @EventListener
    @Async
    public void handleDeferredEvent(DeferredEvent deferredEvent) {
        webhookEventProducer.produceDeferredEvent(deferredEvent.credentialOfferId(), deferredEvent.clientAgentInfo());
        log.info("Processed DeferredEvent for CredentialOfferId: {}", deferredEvent.credentialOfferId());
    }
}