package ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine;

import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.Message;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineBuilder;
import org.springframework.statemachine.config.configurers.StateConfigurer;
import org.springframework.statemachine.guard.Guard;
import org.springframework.stereotype.Component;

import java.util.EnumSet;

/**
 * Factory for creating isolated, per-request {@link StateMachine} instances.
 *
 * <p>Each call to {@link #createManagementStateMachine()} or {@link #createOfferStateMachine()}
 * returns a fresh instance, ensuring thread safety under concurrent requests.</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CredentialStateMachineFactory {

    private final EventProducerAction eventActions;
    private final CredentialOfferAction offerActions;
    private final CredentialManagementAction managementActions;

    /**
     * Creates a new credential management state machine instance.
     *
     * @return a fresh, auto-started {@link StateMachine} for credential management transitions
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public StateMachine<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> createManagementStateMachine() {
        StateMachineBuilder.Builder<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> builder = StateMachineBuilder.builder();

        try {
            builder.configureStates()
                    .withStates()
                    .initial(CredentialStatusManagementType.INIT)
                    .states(EnumSet.allOf(CredentialStatusManagementType.class));

            builder.configureTransitions()
                    .withExternal()
                    .source(CredentialStatusManagementType.INIT).target(CredentialStatusManagementType.ISSUED)
                    .event(CredentialStateMachineConfig.CredentialManagementEvent.ISSUE)
                    .action(eventActions.managementStateChangeAction())
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.SUSPENDED)
                    .event(CredentialStateMachineConfig.CredentialManagementEvent.SUSPEND)
                    .action(eventActions.managementStateChangeAction())
                    .action(managementActions.suspendAction())
                    .name(addNote("Suspend all accociated VCs"))
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.ISSUED)
                    .event(CredentialStateMachineConfig.CredentialManagementEvent.ISSUE)
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.SUSPENDED).target(CredentialStatusManagementType.ISSUED)
                    .event(CredentialStateMachineConfig.CredentialManagementEvent.ISSUE)
                    .action(eventActions.managementStateChangeAction())
                    .action(managementActions.revalidateAction())
                    .name(addNote("Revalidate all accociated VCs"))
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.REVOKED)
                    .event(CredentialStateMachineConfig.CredentialManagementEvent.REVOKE)
                    .action(eventActions.managementStateChangeAction())
                    .action(managementActions.revokeAction())
                    .name(addNote("Revoke all accociated VCs"))
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.SUSPENDED).target(CredentialStatusManagementType.REVOKED)
                    .event(CredentialStateMachineConfig.CredentialManagementEvent.REVOKE)
                    .action(eventActions.managementStateChangeAction())
                    .action(managementActions.revokeAction())
                    .name(addNote("Revoke all accociated VCs"))
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.REVOKED).target(CredentialStatusManagementType.REVOKED)
                    .event(CredentialStateMachineConfig.CredentialManagementEvent.REVOKE)
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.SUSPENDED).target(CredentialStatusManagementType.SUSPENDED)
                    .event(CredentialStateMachineConfig.CredentialManagementEvent.SUSPEND);

            builder.configureConfiguration()
                    .withConfiguration()
                    .autoStartup(true);

            return builder.build();
        } catch (Exception e) {
            log.error("Error building CredentialManagement State Machine", e);
            throw new ConfigurationException("Error building CredentialManagement State Machine", e);
        }
    }

    /**
     * Creates a new credential offer state machine instance.
     *
     * @return a fresh, auto-started {@link StateMachine} for credential offer transitions
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public StateMachine<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> createOfferStateMachine() {
        StateMachineBuilder.Builder<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> builder = StateMachineBuilder.builder();

        try {
            StateConfigurer<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> stateConfigurer = builder.configureStates()
                    .withStates()
                    .initial(CredentialOfferStatusType.INIT)
                    .states(CredentialOfferStatusType.getProcessableStates());
            CredentialOfferStatusType.getTerminalStates().forEach(state -> stateConfigurer.stateEntry(state, offerActions.invalidateOfferDataAction()));

            builder.configureTransitions()
                    // Initial transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.INIT).target(CredentialOfferStatusType.OFFERED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CREATED)
                    .action(eventActions.offerStateChange())
                    .name(addNote("Only for initial\n requests\nnot renewal"))
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.INIT).target(CredentialOfferStatusType.REQUESTED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CREATED)
                    .action(eventActions.offerStateChange())
                    .name(addNote("Only for renewal\n requests"))
                    .and()

                    // Renewal transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.ISSUE)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE)
                    .action(eventActions.offerStateChange())
                    .and()

                    // OFFERED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL)
                    .action(eventActions.offerStateChange())
                    .name(addNote("Process can be\ncancelled as long\nas the vc is not ISSUED"))
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.IN_PROGRESS)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CLAIM)
                    .action(eventActions.offerStateChange())
                    .and()

                    // IN_PROGRESS transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.DEFERRED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.DEFER)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.ISSUE)
                    .action(eventActions.offerStateChange())
                    .name(addNote("only no deferred"))
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL)
                    .action(eventActions.offerStateChange())
                    .and()

                    // DEFERRED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.READY)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.READY)
                    .action(eventActions.offerStateChange())
                    .guard(deferredOfferOnlyGuard())
                    .name("[isDeferredOffer]" + addNote("Guard to allow\nREADY transition\nonly for deferred offers"))
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL)
                    .action(eventActions.offerStateChange())
                    .and()

                    // READY transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.ISSUE)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL)
                    .action(eventActions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.READY)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.READY)
                    .and()

                    // ISSUED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.ISSUED).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.ISSUE)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.ISSUED).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL)
                    .and()

                    // CANCELLED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.CANCELLED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL)
                    .and()

                    // EXPIRED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.EXPIRED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL)
                    .and();

            builder.configureConfiguration()
                    .withConfiguration()
                    .autoStartup(true);

            return builder.build();
        } catch (Exception e) {
            log.error("Error building CredentialOffer State Machine", e);
            throw new ConfigurationException("Error building CredentialOffer State Machine", e);
        }
    }

    private static Guard<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> deferredOfferOnlyGuard() {
        return context -> {
            Message<CredentialStateMachineConfig.CredentialOfferEvent> message = context.getMessage();
            if (message != null && message.getHeaders().containsKey(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER)) {
                Object offerObj = message.getHeaders().get(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER);
                if (offerObj instanceof CredentialOffer offer) {
                    return offer.isDeferredOffer();
                }
            }
            return false;
        };
    }

    private static String addNote(String s) {
        return "\nnote on link\n" +
                s + "\n" +
                "end note\n";
    }
}
