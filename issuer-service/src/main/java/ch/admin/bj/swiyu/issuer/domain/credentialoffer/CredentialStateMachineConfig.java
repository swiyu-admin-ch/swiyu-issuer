package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineBuilder;
import org.springframework.statemachine.config.configurers.StateConfigurer;
import org.springframework.statemachine.guard.Guard;

import java.util.EnumSet;

/**
 * Configuration for credential state machines.
 * Provides beans for credential management and offer state machines.
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class CredentialStateMachineConfig {
    private static final String INVALIDATE_OFFER_DATA = "invalidateOfferData()";
    public static final String CREDENTIAL_OFFER_HEADER = "credential_offer";
    public static final String CREDENTIAL_MANAGEMENT_HEADER = "credential_management";

    private final CredentialStateMachineAction actions;

    /**
     * Events for credential management state machine.
     */
    public enum CredentialManagementEvent {
        ISSUE,
        SUSPEND,
        REVOKE
    }

    /**
     * Events for credential offer state machine.
     */
    @Getter
    public enum CredentialOfferEvent {
        CREATED("Created at start"),
        OFFER("Offer"),
        CLAIM("Claim"),
        DEFER("Defer"),
        READY("Ready"),
        ISSUE("Issue"),
        EXPIRE("Expire"),
        CANCEL("Cancel"),
        REQUEST("Request");

        private final String displayName;

        CredentialOfferEvent(String displayName) {
            this.displayName = displayName;
        }
    }

    /**
     * Creates the credential management state machine bean.
     *
     * @return StateMachine for credential management
     */
    @Bean
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public StateMachine<CredentialStatusManagementType, CredentialManagementEvent> credentialManagementStateMachine() {
        StateMachineBuilder.Builder<CredentialStatusManagementType, CredentialManagementEvent> builder = StateMachineBuilder.builder();

        try {
            builder.configureStates()
                    .withStates()
                    .initial(CredentialStatusManagementType.INIT)
                    .states(EnumSet.allOf(CredentialStatusManagementType.class));


            builder.configureTransitions()
                    .withExternal()
                    .source(CredentialStatusManagementType.INIT).target(CredentialStatusManagementType.ISSUED)
                    .event(CredentialManagementEvent.ISSUE)
                    .action(actions.managementStateChangeAction())
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.SUSPENDED)
                    .event(CredentialManagementEvent.SUSPEND)
                    .action(actions.managementStateChangeAction())
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.ISSUED)
                    .event(CredentialManagementEvent.ISSUE)
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.SUSPENDED).target(CredentialStatusManagementType.ISSUED)
                    .event(CredentialManagementEvent.ISSUE)
                    .action(actions.managementStateChangeAction()) // maybe allow re-issue
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.REVOKED)
                    .event(CredentialManagementEvent.REVOKE)
                    .action(actions.managementStateChangeAction())
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.SUSPENDED).target(CredentialStatusManagementType.REVOKED)
                    .event(CredentialManagementEvent.REVOKE)
                    .action(actions.managementStateChangeAction())
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.REVOKED).target(CredentialStatusManagementType.REVOKED)
                    .event(CredentialManagementEvent.REVOKE)
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.SUSPENDED).target(CredentialStatusManagementType.SUSPENDED)
                    .event(CredentialManagementEvent.SUSPEND);


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
     * Guard to allow READY transition only for deferred offers.
     *
     * @return Guard for deferred offers
     */
    private static Guard<CredentialOfferStatusType, CredentialOfferEvent> deferredOfferOnlyGuard() {
        return context -> {
            Message<CredentialOfferEvent> message = context.getMessage();
            if (message != null && message.getHeaders().containsKey(CREDENTIAL_OFFER_HEADER)) {
                Object offerObj = message.getHeaders().get(CREDENTIAL_OFFER_HEADER);
                if (offerObj instanceof CredentialOffer offer) {
                    return offer.isDeferredOffer();
                }
            }
            return false;
        };
    }

    /**
     * Creates the credential offer state machine bean.
     *
     * @return StateMachine for credential offers
     */
    @Bean
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public StateMachine<CredentialOfferStatusType, CredentialOfferEvent> credentialOfferStateMachine() {
        StateMachineBuilder.Builder<CredentialOfferStatusType, CredentialOfferEvent> builder = StateMachineBuilder.builder();

        try {
            StateConfigurer<CredentialOfferStatusType, CredentialOfferEvent> stateConfigurer = builder.configureStates()
                    .withStates()
                    .initial(CredentialOfferStatusType.INIT)
                    // non terminal states
                    .states(CredentialOfferStatusType.getProcessableStates());

            CredentialOfferStatusType.getTerminalStates().forEach(state -> stateConfigurer.stateEntry(state, actions.invalidateOfferDataAction()));

            builder.configureTransitions()
                    // Initial transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.INIT).target(CredentialOfferStatusType.OFFERED)
                    .event(CredentialOfferEvent.CREATED)
                    .action(actions.offerStateChange())
                    .name(addNote("Only for initial\n requests\nnot renewal"))
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.INIT).target(CredentialOfferStatusType.REQUESTED)
                    .event(CredentialOfferEvent.CREATED)
                    .action(actions.offerStateChange())
                    .name(addNote("Only for renewal\n requests"))
                    .and()

                    // Renewal transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialOfferEvent.ISSUE)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(actions.offerStateChange())
                    .and()

                    // OFFERED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
                    .action(actions.offerStateChange())
                    .name(addNote("Process can be\ncancelled as long\nas the vc is not ISSUED"))
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.IN_PROGRESS)
                    .event(CredentialOfferEvent.CLAIM)
                    .action(actions.offerStateChange())
                    .and()

                    // IN_PROGRESS transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.DEFERRED)
                    .event(CredentialOfferEvent.DEFER)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialOfferEvent.ISSUE)
                    .action(actions.offerStateChange())
                    .name(addNote("only no deferred"))
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
                    .action(actions.offerStateChange())
                    .and()

                    // DEFERRED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.READY)
                    .event(CredentialOfferEvent.READY)
                    .action(actions.offerStateChange())
                    .guard(deferredOfferOnlyGuard())
                    .name("[isDeferredOffer]" + addNote("Guard to allow\nREADY transition\nonly for deferred offers"))
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
                    .action(actions.offerStateChange())
                    .and()

                    // READY transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialOfferEvent.ISSUE)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
                    .action(actions.offerStateChange())
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.READY)
                    .event(CredentialOfferEvent.READY)
                    .and()

                    // ISSUED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.ISSUED).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialOfferEvent.ISSUE)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.ISSUED).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialOfferEvent.CANCEL)
                    .and()

                    // CANCELLED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.CANCELLED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
                    .and()

                    // EXPIRED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.EXPIRED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.CANCEL)
                    .and();

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
     * Adds a PlantUML note to a transition.
     *
     * @param s Note text
     * @return PlantUML note string
     */
    private String addNote(String s) {
        return "\nnote on link\n" +
                s + "\n" +
                "end note\n";
    }
}
