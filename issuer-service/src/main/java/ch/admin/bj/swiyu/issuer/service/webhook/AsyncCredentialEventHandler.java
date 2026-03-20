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

    /**
     * Triggered after a successful transaction commit.
     *
     * The annotation @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT) ensures that the webhook event
     * is only sent to the Business Issuer if the state change has actually been persisted in the database.
     * This prevents so-called "ghost webhooks" (false positives) where a webhook is sent,
     * but the transaction is later rolled back (e.g., due to a failure updating the Status List).
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    @Async
    public void handleOfferStateChangeEvent(OfferStateChangeEvent stateChangeEvent) {
        webhookEventProducer.produceOfferStateChangeEvent(stateChangeEvent.credentialOfferId(), stateChangeEvent.newState());
        log.info("Processed StateChangeEvent for CredentialOfferId: {}", stateChangeEvent.credentialOfferId());
    }

    /**
     * Triggered after a transaction rollback.
     *
     * The annotation @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK) ensures that in case of a failure
     * (e.g., if updating the external Status List fails), an error webhook is sent to the Business Issuer.
     * This keeps both systems in sync regarding failed operations.
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    @Async
    public void handleOfferStateChangeRollback(OfferStateChangeEvent stateChangeEvent) {
        log.warn("Transaction rolled back for CredentialOfferId: {} – attempted state: {}. Sending error event.",
                stateChangeEvent.credentialOfferId(), stateChangeEvent.newState());
        webhookEventProducer.produceErrorEvent(stateChangeEvent.credentialOfferId(), CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED,
                "Status list update failed for state transition to " + stateChangeEvent.newState(), CallbackEventTrigger.CREDENTIAL_OFFER);
    }

    /**
     * Triggered after a successful transaction commit.
     *
     * The annotation @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT) ensures that the webhook event
     * is only sent to the Business Issuer if the state change has actually been persisted in the database.
     * This prevents so-called "ghost webhooks" (false positives) where a webhook is sent,
     * but the transaction is later rolled back (e.g., due to a failure updating the Status List).
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    @Async
    public void handleManagementStateChangeEvent(ManagementStateChangeEvent managementStateChangeEvent) {
        webhookEventProducer.produceManagementStateChangeEvent(managementStateChangeEvent.credentialManagementId(), managementStateChangeEvent.newState());
        log.info("Processed StateChangeEvent for CredentialManagementId: {}", managementStateChangeEvent.credentialManagementId());
    }

    /**
     * Triggered after a transaction rollback.
     *
     * The annotation @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK) ensures that in case of a failure
     * (e.g., if updating the external Status List fails), an error webhook is sent to the Business Issuer.
     * This keeps both systems in sync regarding failed operations.
     */
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