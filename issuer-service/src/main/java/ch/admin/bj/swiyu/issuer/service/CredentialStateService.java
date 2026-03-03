package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachine;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.service.management.CredentialManagementMapper;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListPersistenceService;
import ch.admin.bj.swiyu.issuer.service.webhook.OfferStateChangeEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
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
    private final StatusListPersistenceService statusListPersistenceService;


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
                credentialOffer.getId(),
                credentialOffer.getCredentialStatus());

        persistenceService.saveCredentialOffer(credentialOffer);
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
     * Publishes a state change event for a credential offer.
     *
     * @param credentialOfferId      the credential offer ID
     * @param state                  the new state
     */
    private void publishOfferStateChangeEvent(
            UUID credentialOfferId,
            CredentialOfferStatusType state) {

        var stateChangeEvent = new OfferStateChangeEvent(
                credentialOfferId,
                state);
        applicationEventPublisher.publishEvent(stateChangeEvent);
    }


    /**
     * Handle status changes for post-issuance process.
     * In post-issuance, the CredentialManagement status is leading.
     */
    public UpdateStatusResponseDto handleStatusChange(
            CredentialManagement mgmt,
            CredentialStateMachineConfig.CredentialManagementEvent managementEvent,
            CredentialStateMachineConfig.CredentialOfferEvent offerEvent) {

        // Update states using state service. If event is null, state machine will not perform a transition, but we
        // can still get the current status to determine if we need to update status lists.        var managementResult = credentialStateMachine.sendEventAndUpdateStatus(mgmt, managementEvent);
        credentialStateMachine.sendEventAndUpdateStatus(mgmt, managementEvent);
        mgmt.getCredentialOffers().stream().forEach(o -> credentialStateMachine.sendEventAndUpdateStatus(o, offerEvent));
        List<UUID> statusLists = null;
        return CredentialManagementMapper.toUpdateStatusResponseDto(mgmt, statusLists);
    }

    /**
     * Updates the status list based on the management status.
     * Dispatches to the correct status list operation without requiring the status type as a parameter
     * to the orchestrator methods.
     *
     * @param offerStatusSet the credential offer statuses to update
     * @param newStatus the new management status
     * @return the list of affected status list IDs
     */
    private List<UUID> updateStatusListBasedOnManagementStatus(
            Set<CredentialOfferStatus> offerStatusSet,
            CredentialStatusManagementType newStatus) {

        return switch (newStatus) {
            case REVOKED -> statusListPersistenceService.revoke(offerStatusSet);
            case SUSPENDED -> statusListPersistenceService.suspend(offerStatusSet);
            case ISSUED -> statusListPersistenceService.revalidate(offerStatusSet);
            default -> throw new IllegalStateException(
                    "Unexpected management status for post-issuance: " + newStatus);
        };
    }
}
