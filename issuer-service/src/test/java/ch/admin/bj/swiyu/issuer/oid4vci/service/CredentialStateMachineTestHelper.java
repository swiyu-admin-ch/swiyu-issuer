package ch.admin.bj.swiyu.issuer.oid4vci.service;

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
            switch (event) {
                case ISSUE -> {
                    entity.setCredentialManagementStatusJustForTestUsage(CredentialStatusManagementType.ISSUED);
                    return CredentialStatusManagementType.ISSUED;
                }
                case SUSPEND -> {
                    entity.setCredentialManagementStatusJustForTestUsage(CredentialStatusManagementType.SUSPENDED);
                    return CredentialStatusManagementType.SUSPENDED;
                }
                case REVOKE -> {
                    entity.setCredentialManagementStatusJustForTestUsage(CredentialStatusManagementType.REVOKED);
                    return CredentialStatusManagementType.REVOKED;
                }
                default -> {
                    // No action needed for other events in test mock
                }
            }
            return null;
        }).when(credentialStateMachine).sendEventAndUpdateStatus(
                Mockito.any(CredentialManagement.class),
                Mockito.any(CredentialStateMachineConfig.CredentialManagementEvent.class)
        );

        // Mock sendEventAndUpdateStatus for CredentialOffer
        Mockito.doAnswer(invocation -> {
            CredentialOffer entity = invocation.getArgument(0);
            CredentialStateMachineConfig.CredentialOfferEvent event = invocation.getArgument(1);
            switch (event) {
                case ISSUE -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.ISSUED);
                    entity.invalidateOfferData();
                    return CredentialOfferStatusType.ISSUED;
                }
                case EXPIRE -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.EXPIRED);
                    entity.invalidateOfferData();
                    return CredentialOfferStatusType.EXPIRED;
                }
                case CANCEL -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.CANCELLED);
                    entity.invalidateOfferData();
                    return CredentialOfferStatusType.CANCELLED;
                }
                case DEFER -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.DEFERRED);
                    return CredentialOfferStatusType.DEFERRED;
                }
                case READY -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.READY);
                    return CredentialOfferStatusType.READY;
                }
                case OFFER -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.OFFERED);
                    return CredentialOfferStatusType.OFFERED;
                }
                case CLAIM -> {
                    entity.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.IN_PROGRESS);
                    return CredentialOfferStatusType.IN_PROGRESS;
                }
                default -> {
                    // No action needed for other events in test mock
                }
            }
            return null;
        }).when(credentialStateMachine).sendEventAndUpdateStatus(
                Mockito.any(CredentialOffer.class),
                Mockito.any(CredentialStateMachineConfig.CredentialOfferEvent.class)
        );

    }
}
