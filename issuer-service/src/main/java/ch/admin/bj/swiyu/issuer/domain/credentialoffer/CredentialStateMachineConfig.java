package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.action.Action;
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

    public static final String CREDENTIAL_OFFER_HEADER = "credential_offer";

    public static Action<CredentialOfferStatusType, CredentialOfferEvent> invalidateOfferDataAction() {
        return context -> {
            Message<CredentialOfferEvent> message = context.getMessage();
            if (message != null && message.getHeaders().containsKey(CREDENTIAL_OFFER_HEADER)) {
                Object offerObj = message.getHeaders().get(CREDENTIAL_OFFER_HEADER);
                if (offerObj instanceof CredentialOffer offer) {
                    offer.invalidateOfferData();
                }
            }
        };
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
                .event(CredentialOfferEvent.EXPIRE)
                .action(invalidateOfferDataAction()).name("invalidateOfferData")
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.IN_PROGRESS)
                .event(CredentialOfferEvent.CLAIM)
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.REQUESTED)
                .event(CredentialOfferEvent.REQUEST)
                .and()

                // IN_PROGRESS transitions
                .withExternal()
                .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.EXPIRED)
                .event(CredentialOfferEvent.EXPIRE)
                .action(invalidateOfferDataAction()).name("invalidateOfferData")
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.DEFERRED)
                .event(CredentialOfferEvent.DEFER)
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.ISSUED)
                .event(CredentialOfferEvent.ISSUE)
                .action(invalidateOfferDataAction()).name("invalidateOfferData")
                .and()
                // DEFERRED transitions
                .withExternal()
                .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.READY)
                .event(CredentialOfferEvent.READY)
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.EXPIRED)
                .event(CredentialOfferEvent.EXPIRE)
                .action(invalidateOfferDataAction()).name("invalidateOfferData")
                .and()
                // READY transitions
                .withExternal()
                .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.ISSUED)
                .event(CredentialOfferEvent.ISSUE)
                .action(invalidateOfferDataAction()).name("invalidateOfferData")
                .and()
                .withExternal()
                .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.EXPIRED)
                .event(CredentialOfferEvent.EXPIRE)
                .action(invalidateOfferDataAction()).name("invalidateOfferData")
                .and();

        builder.configureConfiguration()
                .withConfiguration()
                .autoStartup(true);

        return builder.build();
    }
}
