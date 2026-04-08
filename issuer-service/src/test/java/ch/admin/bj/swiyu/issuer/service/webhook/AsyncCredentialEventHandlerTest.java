package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventTrigger;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.dto.callback.CallbackErrorEventTypeDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Unit tests for {@link AsyncCredentialEventHandler}.
 *
 * <p>Verifies that on a successful transaction commit the correct state-change webhook is produced,
 * and that on a transaction rollback a {@link CallbackErrorEventTypeDto#STATUS_LIST_UPDATE_FAILED}
 * error event is sent instead – so no false-positive webhook is delivered to the Business Issuer.
 */
class AsyncCredentialEventHandlerTest {

    private WebhookEventProducer webhookEventProducer;
    private AsyncCredentialEventHandler handler;

    @BeforeEach
    void setUp() {
        webhookEventProducer = mock(WebhookEventProducer.class);
        handler = new AsyncCredentialEventHandler(webhookEventProducer);
    }

    // ── ManagementStateChangeEvent ──────────────────────────────────────────────

    @Test
    void handleManagementStateChangeEvent_onCommit_producesStateChangeEvent() {
        var credentialManagementId = UUID.randomUUID();
        var event = new ManagementStateChangeEvent(credentialManagementId, CredentialStatusManagementType.REVOKED);

        handler.handleManagementStateChangeEvent(event);

        verify(webhookEventProducer).produceManagementStateChangeEvent(credentialManagementId, CredentialStatusManagementType.REVOKED);
        verifyNoMoreInteractions(webhookEventProducer);
    }

    @Test
    void handleManagementStateChangeRollback_onRollback_producesErrorEvent() {
        var credentialManagementId = UUID.randomUUID();
        var event = new ManagementStateChangeEvent(credentialManagementId, CredentialStatusManagementType.REVOKED);

        handler.handleManagementStateChangeRollback(event);

        verify(webhookEventProducer).produceErrorEvent(
                credentialManagementId,
                CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED,
                "Status list update failed for state transition to " + CredentialStatusManagementType.REVOKED,
                CallbackEventTrigger.CREDENTIAL_MANAGEMENT
        );
        verifyNoMoreInteractions(webhookEventProducer);
    }

    @Test
    void handleManagementStateChangeRollback_doesNotProduceStateChangeEvent() {
        var event = new ManagementStateChangeEvent(UUID.randomUUID(), CredentialStatusManagementType.SUSPENDED);

        handler.handleManagementStateChangeRollback(event);

        verify(webhookEventProducer).produceErrorEvent(
                event.credentialManagementId(),
                CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED,
                "Status list update failed for state transition to " + CredentialStatusManagementType.SUSPENDED,
                CallbackEventTrigger.CREDENTIAL_MANAGEMENT
        );
        verifyNoMoreInteractions(webhookEventProducer);
    }

    // ── OfferStateChangeEvent ───────────────────────────────────────────────────

    @Test
    void handleOfferStateChangeEvent_onCommit_producesStateChangeEvent() {
        var credentialOfferId = UUID.randomUUID();
        var event = new OfferStateChangeEvent(credentialOfferId, CredentialOfferStatusType.ISSUED);

        handler.handleOfferStateChangeEvent(event);

        verify(webhookEventProducer).produceOfferStateChangeEvent(credentialOfferId, CredentialOfferStatusType.ISSUED);
        verifyNoMoreInteractions(webhookEventProducer);
    }

    @Test
    void handleOfferStateChangeRollback_onRollback_producesErrorEvent() {
        var credentialOfferId = UUID.randomUUID();
        var event = new OfferStateChangeEvent(credentialOfferId, CredentialOfferStatusType.ISSUED);

        handler.handleOfferStateChangeRollback(event);

        verify(webhookEventProducer).produceErrorEvent(
                credentialOfferId,
                CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED,
                "Status list update failed for state transition to " + CredentialOfferStatusType.ISSUED,
                CallbackEventTrigger.CREDENTIAL_OFFER
        );
        verifyNoMoreInteractions(webhookEventProducer);
    }

    @Test
    void handleOfferStateChangeRollback_doesNotProduceStateChangeEvent() {
        var event = new OfferStateChangeEvent(UUID.randomUUID(), CredentialOfferStatusType.EXPIRED);

        handler.handleOfferStateChangeRollback(event);

        verify(webhookEventProducer).produceErrorEvent(
                event.credentialOfferId(),
                CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED,
                "Status list update failed for state transition to " + CredentialOfferStatusType.EXPIRED,
                CallbackEventTrigger.CREDENTIAL_OFFER
        );
        verifyNoMoreInteractions(webhookEventProducer);
    }
}

