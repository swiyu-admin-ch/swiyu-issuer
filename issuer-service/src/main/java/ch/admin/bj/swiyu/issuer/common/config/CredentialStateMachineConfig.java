package ch.admin.bj.swiyu.issuer.common.config;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineBuilder;

import java.util.EnumSet;

@Configuration
@Slf4j
public class CredentialStateMachineConfig {

    public enum CredentialManagementEvent {
        ISSUE,
        SUSPEND,
        REVOKE
    }

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

    @Bean
    public StateMachine<CredentialStatusManagementType, CredentialManagementEvent> credentialManagementStateMachine() throws Exception {
        StateMachineBuilder.Builder<CredentialStatusManagementType, CredentialManagementEvent> builder = StateMachineBuilder.builder();

        builder.configureStates()
                .withStates()
                .initial(CredentialStatusManagementType.INIT)
                .states(EnumSet.allOf(CredentialStatusManagementType.class));

        builder.configureTransitions()
                .withExternal()
                .source(CredentialStatusManagementType.INIT).target(CredentialStatusManagementType.ISSUED)
                .event(CredentialManagementEvent.ISSUE)
                .and()
                .withExternal()
                .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.SUSPENDED)
                .event(CredentialManagementEvent.SUSPEND)
                .and()
                .withExternal()
                .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.ISSUED)
                .event(CredentialManagementEvent.ISSUE)
                .and()
                .withExternal()
                .source(CredentialStatusManagementType.SUSPENDED).target(CredentialStatusManagementType.ISSUED)
                .event(CredentialManagementEvent.ISSUE) // maybe allow re-issue
                .and()
                .withExternal()
                .source(CredentialStatusManagementType.ISSUED).target(CredentialStatusManagementType.REVOKED)
                .event(CredentialManagementEvent.REVOKE);

        builder.configureConfiguration()
                .withConfiguration()
                .autoStartup(true);

        return builder.build();
    }

    @Bean
    public StateMachine<CredentialOfferStatusType, CredentialOfferEvent> credentialOfferStateMachine() throws Exception {
        StateMachineBuilder.Builder<CredentialOfferStatusType, CredentialOfferEvent> builder = StateMachineBuilder.builder();

        builder.configureStates()
                .withStates()
                .initial(CredentialOfferStatusType.INIT)
                .states(EnumSet.allOf(CredentialOfferStatusType.class));

        builder.configureTransitions()
                // Initialtransitions
                .withExternal()
                .source(CredentialOfferStatusType.INIT).target(CredentialOfferStatusType.OFFERED)
                .event(CredentialOfferEvent.CREATED)
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.INIT).target(CredentialOfferStatusType.REQUESTED)
                .event(CredentialOfferEvent.CREATED)
                .and()

                // Renewal transitions
                .withExternal()
                .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.ISSUED)
                .event(CredentialOfferEvent.ISSUE)
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.CANCELLED)
                .event(CredentialOfferEvent.CANCEL)
                .and()

                // OFFERED transitions
                .withExternal()
                .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.CANCELLED)
                .event(CredentialOfferEvent.CANCEL) // Process can be cancelled as long as the vc is not ISSUED
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.EXPIRED)
                .event(CredentialOfferEvent.EXPIRE) // When deferred-offer-validity-seconds passed
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.IN_PROGRESS)
                .event(CredentialOfferEvent.CLAIM)
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.REQUESTED)
                .event(CredentialOfferEvent.REQUEST)
                .and()

                // CANCELLED transitions
//                .withExternal()
//                .source(CredentialOfferStatusType.CANCELLED).target(CredentialOfferStatusType.OFFERED)
//                .event(CredentialOfferEvent.OFFER) // CANCELLED ---> [*] (PlantUML End)
//                .and()
                // IN_PROGRESS transitions
                .withExternal()
                .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.EXPIRED)
                .event(CredentialOfferEvent.EXPIRE) // Can expire on status (OFFERED, IN_PROGRESS)
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.DEFERRED)
                .event(CredentialOfferEvent.DEFER) // Deferred = true
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.ISSUED)
                .event(CredentialOfferEvent.ISSUE) // Non-deferred flow
                .and()
                // DEFERRED transitions
                .withExternal()
                .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.READY)
                .event(CredentialOfferEvent.READY) // Status READY must be set by the business issuer
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.EXPIRED)
                .event(CredentialOfferEvent.EXPIRE) // When deferred-offer-validity-seconds passed
                .and()
                // READY transitions
                .withExternal()
                .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.ISSUED)
                .event(CredentialOfferEvent.ISSUE)
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.EXPIRED)
                .event(CredentialOfferEvent.EXPIRE); // When deferred-offer-validity-seconds passed

                // ISSUED transitions
//                .withExternal()
//                .source(CredentialOfferStatusType.ISSUED).target(CredentialOfferStatusType.OFFERED)
//                .event(CredentialOfferEvent.OFFER) // ISSUED --> [*] (PlantUML End)
//                .and()
                // EXPIRED transitions
//                .withExternal()
//                .source(CredentialOfferStatusType.EXPIRED).target(CredentialOfferStatusType.OFFERED)
//                .event(CredentialOfferEvent.OFFER); // EXPIRED --> [*] (PlantUML End)

        builder.configureConfiguration()
                .withConfiguration()
                .autoStartup(true);

        return builder.build();
    }
}
