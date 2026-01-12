package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachine;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachineConfig;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.service.mapper.CredentialManagementMapper;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.webhook.OfferStateChangeEvent;
import ch.admin.bj.swiyu.issuer.service.webhook.StateChangeEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Service responsible for managing credential state transitions and publishing state change events.
 *
 * <p>This service encapsulates all state machine orchestration and event publishing logic,
 * separating it from the main business logic of credential management.</p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialStateService {

    private final CredentialStateMachine credentialStateMachine;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final CredentialPersistenceService persistenceService;
    private final StatusListManagementService statusListManagementService;

    /**
     * Updates the credential offer state and publishes an event if the state changed.
     *
     * @param credentialOffer        the credential offer to update
     * @param event                  the state machine event
     * @param credentialManagementId the management ID for event publishing
     * @return the result of the state transition
     */
    public CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType> updateOfferStateAndPublish(
            CredentialOffer credentialOffer,
            CredentialStateMachineConfig.CredentialOfferEvent event,
            UUID credentialManagementId) {

        var result = credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, event);

        if (result.changed()) {
            log.debug("Updating credential offer {} from previous state to {}",
                    credentialOffer.getId(), result.newStatus());

            publishOfferStateChangeEvent(credentialManagementId, credentialOffer.getId(), result.newStatus());
        }

        return result;
    }

    /**
     * Updates the credential management state and publishes an event if the state changed.
     *
     * @param credentialManagement the credential management to update
     * @param event                the state machine event
     * @return the result of the state transition
     */
    public CredentialStateMachine.StateTransitionResult<CredentialStatusManagementType> updateManagementStateAndPublish(
            CredentialManagement credentialManagement,
            CredentialStateMachineConfig.CredentialManagementEvent event) {

        var result = credentialStateMachine.sendEventAndUpdateStatus(credentialManagement, event);

        if (result.changed()) {
            log.debug("Updating credential management {} from previous state to {}",
                    credentialManagement.getId(), result.newStatus());

            publishStateChangeEvent(credentialManagement.getId(), result.newStatus());
        }

        return result;
    }

    /**
     * Updates both offer and management states for pre-issuance process.
     * In pre-issuance, the CredentialOffer status is leading.
     *
     * @param credentialManagement the credential management
     * @param credentialOffer      the credential offer
     * @param managementEvent      the management event
     * @param offerEvent           the offer event
     * @return the offer state transition result
     */
    public CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType> handlePreIssuanceStateTransition(
            CredentialManagement credentialManagement,
            CredentialOffer credentialOffer,
            CredentialStateMachineConfig.CredentialManagementEvent managementEvent,
            CredentialStateMachineConfig.CredentialOfferEvent offerEvent) {

        // Update CredentialOffer state first (leading in pre-issuance)
        var offerResult = updateOfferStateAndPublish(
                credentialOffer,
                offerEvent,
                credentialManagement.getId());

        // Update CredentialManagement state
        credentialStateMachine.sendEventAndUpdateStatus(credentialManagement, managementEvent);

        return offerResult;
    }

    /**
     * Updates both offer and management states for post-issuance process.
     * In post-issuance, the CredentialManagement status is leading.
     *
     * @param credentialManagement the credential management
     * @param credentialOffer      the credential offer
     * @param managementEvent      the management event
     * @param offerEvent           the offer event
     * @return the management state transition result
     */
    public CredentialStateMachine.StateTransitionResult<CredentialStatusManagementType> handlePostIssuanceStateTransition(
            CredentialManagement credentialManagement,
            CredentialOffer credentialOffer,
            CredentialStateMachineConfig.CredentialManagementEvent managementEvent,
            CredentialStateMachineConfig.CredentialOfferEvent offerEvent) {

        // Update CredentialManagement state first (leading in post-issuance)
        var managementResult = updateManagementStateAndPublish(credentialManagement, managementEvent);

        // Update CredentialOffer state
        credentialStateMachine.sendEventAndUpdateStatus(credentialOffer, offerEvent);

        return managementResult;
    }

    /**
     * Updates the offer state to EXPIRED and publishes an event.
     *
     * @param credentialOffer the credential offer to expire
     */
    public void expireOfferAndPublish(CredentialOffer credentialOffer) {
        credentialStateMachine.sendEventAndUpdateStatus(
                credentialOffer,
                CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE);

        publishOfferStateChangeEvent(
                credentialOffer.getCredentialManagement().getId(),
                credentialOffer.getId(),
                credentialOffer.getCredentialStatus());
    }

    /**
     * Updates the offer state to READY.
     *
     * @param credentialOffer the credential offer to mark as ready
     */
    public void markOfferAsReady(CredentialOffer credentialOffer) {
        credentialStateMachine.sendEventAndUpdateStatus(
                credentialOffer,
                CredentialStateMachineConfig.CredentialOfferEvent.READY);
    }

    /**
     * Publishes a state change event for credential management.
     *
     * @param credentialManagementId the credential management ID
     * @param state                  the new state
     */
    private void publishStateChangeEvent(UUID credentialManagementId, CredentialStatusManagementType state) {
        var stateChangeEvent = new StateChangeEvent(credentialManagementId, state);
        applicationEventPublisher.publishEvent(stateChangeEvent);
    }

    /**
     * Publishes a state change event for a credential offer.
     *
     * @param credentialManagementId the credential management ID
     * @param credentialOfferId      the credential offer ID
     * @param state                  the new state
     */
    private void publishOfferStateChangeEvent(
            UUID credentialManagementId,
            UUID credentialOfferId,
            CredentialOfferStatusType state) {

        var stateChangeEvent = new OfferStateChangeEvent(
                credentialManagementId,
                credentialOfferId,
                state);
        applicationEventPublisher.publishEvent(stateChangeEvent);
    }

    /**
     * Handle status changes for pre-issuance process.
     * In pre-issuance, the CredentialOffer status is leading.
     */
    public UpdateStatusResponseDto handleStatusChangeForPreIssuanceProcess(
            CredentialManagement mgmt,
            CredentialOffer credentialOffer,
            CredentialStateMachineConfig.CredentialManagementEvent managementEvent,
            CredentialStateMachineConfig.CredentialOfferEvent offerEvent) {

        // Update states using state service
        var offerResult = handlePreIssuanceStateTransition(
                mgmt, credentialOffer, managementEvent, offerEvent);

        // Only persist if offer state actually changed
        if (offerResult.changed()) {
            persistenceService.saveCredentialOffer(credentialOffer);
        }

        return CredentialManagementMapper.toUpdateStatusResponseDto(mgmt, null);
    }

    /**
     * Handle status changes for post-issuance process.
     * In post-issuance, the CredentialManagement status is leading.
     */
    public UpdateStatusResponseDto handleStatusChangeForPostIssuanceProcess(
            CredentialManagement mgmt,
            CredentialOffer credentialOffer,
            CredentialStateMachineConfig.CredentialManagementEvent managementEvent,
            CredentialStateMachineConfig.CredentialOfferEvent offerEvent) {

        // Update states using state service
        var managementResult = handlePostIssuanceStateTransition(
                mgmt, credentialOffer, managementEvent, offerEvent);

        // Only persist and handle status lists if management state actually changed
        if (!managementResult.changed()) {
            return CredentialManagementMapper.toUpdateStatusResponseDto(mgmt, null);
        }

        // Handle status list updates for post-issuance
        var affectedOffers = mgmt.getCredentialOffers().stream()
                .map(ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer::getId)
                .toList();

        var offerStatusSet = persistenceService.findCredentialOfferStatusesByOfferIds(affectedOffers);
        var statusList = statusListManagementService.updateStatusListsForPostIssuance(
                offerStatusSet, (CredentialStatusManagementType) managementResult.newStatus());

        var updatedMgmt = persistenceService.saveCredentialManagement(mgmt);

        return CredentialManagementMapper.toUpdateStatusResponseDto(updatedMgmt, statusList);
    }
}
