package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import org.mockito.Mockito;

/**
 * Test helper for mocking CredentialStateMachine status updates in tests.
 * Mocks the sendEventAndUpdateStatus methods to set status in the entity for tests.
 */
public class CredentialStateMachineTestHelper {
    /**
     * Mocks the sendEventAndUpdateStatus methods of CredentialStateMachine to set status in the entity for tests.
     *
     * @param credentialStateMachine the CredentialStateMachine mock to configure
     */
    public static void mockCredentialStateMachine(CredentialStateMachine credentialStateMachine) {
        // Mock sendEventAndUpdateStatus for CredentialManagement
        Mockito.doAnswer(invocation -> {
            CredentialManagement entity = invocation.getArgument(0);
            CredentialStateMachineConfig.CredentialManagementEvent event = invocation.getArgument(1);

            var oldStatus = entity.getCredentialManagementStatus();
            CredentialStatusManagementType newStatus = switch (event) {
                case ISSUE -> {
                    entity.setCredentialManagementStatusJustForTestUsage(CredentialStatusManagementType.ISSUED);
                    yield CredentialStatusManagementType.ISSUED;
                }
                case SUSPEND -> {
                    entity.setCredentialManagementStatusJustForTestUsage(CredentialStatusManagementType.SUSPENDED);
                    yield CredentialStatusManagementType.SUSPENDED;
                }
                case REVOKE -> {
                    entity.setCredentialManagementStatusJustForTestUsage(CredentialStatusManagementType.REVOKED);
                    yield CredentialStatusManagementType.REVOKED;
                }
            };
            return new CredentialStateMachine.StateTransitionResult<>(newStatus, oldStatus != newStatus);
        }).when(credentialStateMachine).sendEventAndUpdateStatus(
                Mockito.any(CredentialManagement.class),
                Mockito.any(CredentialStateMachineConfig.CredentialManagementEvent.class)
        );

        // Mock sendEventAndUpdateStatus for CredentialOffer
        Mockito.doAnswer(invocation -> {
            CredentialOffer entity = invocation.getArgument(0);
            CredentialStateMachineConfig.CredentialOfferEvent event = invocation.getArgument(1);

            var oldStatus = entity.getCredentialStatus();
            CredentialOfferStatusType newStatus = switch (event) {
                case ISSUE -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.ISSUED);
                    entity.invalidateOfferData();
                    yield CredentialOfferStatusType.ISSUED;
                }
                case EXPIRE -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.EXPIRED);
                    entity.invalidateOfferData();
                    yield CredentialOfferStatusType.EXPIRED;
                }
                case CANCEL -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.CANCELLED);
                    entity.invalidateOfferData();
                    yield CredentialOfferStatusType.CANCELLED;
                }
                case DEFER -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.DEFERRED);
                    yield CredentialOfferStatusType.DEFERRED;
                }
                case READY -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.READY);
                    yield CredentialOfferStatusType.READY;
                }
                case OFFER -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.OFFERED);
                    yield CredentialOfferStatusType.OFFERED;
                }
                case CLAIM -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.IN_PROGRESS);
                    yield CredentialOfferStatusType.IN_PROGRESS;
                }
                case CREATED, REQUEST -> {
                    // Keep current status for these events
                    yield entity.getCredentialStatus();
                }
            };
            return new CredentialStateMachine.StateTransitionResult<>(newStatus, oldStatus != newStatus);
        }).when(credentialStateMachine).sendEventAndUpdateStatus(
                Mockito.any(CredentialOffer.class),
                Mockito.any(CredentialStateMachineConfig.CredentialOfferEvent.class)
        );

        // explicit null-Event for CredentialOffer
        Mockito.doAnswer(invocation -> {
            CredentialOffer entity = invocation.getArgument(0);
            return new CredentialStateMachine.StateTransitionResult<>(
                    entity.getCredentialStatus(), false);
        }).when(credentialStateMachine).sendEventAndUpdateStatus(
                Mockito.any(CredentialOffer.class),
                Mockito.isNull()
        );

        // explicit null-Event for CredentialManagement
        Mockito.doAnswer(invocation -> {
            CredentialManagement entity = invocation.getArgument(0);
            return new CredentialStateMachine.StateTransitionResult<>(
                    entity.getCredentialManagementStatus(), false);
        }).when(credentialStateMachine).sendEventAndUpdateStatus(
                Mockito.any(CredentialManagement.class),
                Mockito.isNull()
        );
    }
}
