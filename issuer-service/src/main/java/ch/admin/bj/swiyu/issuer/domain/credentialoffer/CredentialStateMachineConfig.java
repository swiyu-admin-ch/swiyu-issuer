package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
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

    private static final String INVALIDATE_OFFER_DATA = "invalidateOfferData";

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
                    .event(CredentialManagementEvent.REVOKE)
                    .and()
                    .withExternal()
                    .source(CredentialStatusManagementType.SUSPENDED).target(CredentialStatusManagementType.REVOKED)
                    .event(CredentialManagementEvent.REVOKE)
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
    public StateMachine<CredentialOfferStatusType, CredentialOfferEvent> credentialOfferStateMachine() {
        StateMachineBuilder.Builder<CredentialOfferStatusType, CredentialOfferEvent> builder = StateMachineBuilder.builder();

        try {
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
                    .withExternal()
                    .source(CredentialOfferStatusType.REQUESTED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .and()

                    // OFFERED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL) // Process can be cancelled as long as the vc is not ISSUED
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(invalidateOfferDataAction()).name(INVALIDATE_OFFER_DATA)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.OFFERED).target(CredentialOfferStatusType.IN_PROGRESS)
                    .event(CredentialOfferEvent.CLAIM)
                    .and()


                    // IN_PROGRESS transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(invalidateOfferDataAction()).name(INVALIDATE_OFFER_DATA)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.DEFERRED)
                    .event(CredentialOfferEvent.DEFER)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialOfferEvent.ISSUE)
                    .action(invalidateOfferDataAction()).name(INVALIDATE_OFFER_DATA)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.IN_PROGRESS).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
                    .action(invalidateOfferDataAction()).name(INVALIDATE_OFFER_DATA)
                    .and()
                    // DEFERRED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.READY)
                    .event(CredentialOfferEvent.READY)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(invalidateOfferDataAction()).name(INVALIDATE_OFFER_DATA)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.DEFERRED).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
                    .action(invalidateOfferDataAction()).name(INVALIDATE_OFFER_DATA)
                    .and()
                    // READY transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.ISSUED)
                    .event(CredentialOfferEvent.ISSUE)
                    .action(invalidateOfferDataAction()).name(INVALIDATE_OFFER_DATA)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.EXPIRED)
                    .event(CredentialOfferEvent.EXPIRE)
                    .action(invalidateOfferDataAction()).name(INVALIDATE_OFFER_DATA)
                    .and()
                    .withExternal()
                    .source(CredentialOfferStatusType.READY).target(CredentialOfferStatusType.CANCELLED)
                    .event(CredentialOfferEvent.CANCEL)
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
                    // CANCELLED transitions
                    .withExternal()
                    .source(CredentialOfferStatusType.CANCELLED).target(CredentialOfferStatusType.CANCELLED)
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
}
