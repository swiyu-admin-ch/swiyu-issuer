package ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.AUTHORIZATION_HEADER;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.BEARER_TOKEN_REGEX;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.BUSINESS_ENTITY_ID;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.COLLECTION_PATH;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.CONSUMER;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.JSON_CONTENT_TYPE_REGEX;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.PROVIDER;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.STATUS_REGISTRY_ENTRY_ID;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.STATUS_REGISTRY_URL;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.buildStatusRegistryClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@PactConsumerTest
@PactTestFor(providerName = PROVIDER, pactVersion = PactSpecVersion.V4)
class StatusListEntryCreationConsumerPactTest {

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact statusListEntryCreated(final PactDslWithProvider builder) {
        return builder
                .given("a status list entry can be created for a business entity",
                        Map.of(
                                "businessEntityId", BUSINESS_ENTITY_ID.toString(),
                                "statusRegistryEntryId", STATUS_REGISTRY_ENTRY_ID.toString(),
                                "statusRegistryUrl", STATUS_REGISTRY_URL))
                .uponReceiving("POST a status list entry for a business entity")
                .method("POST")
                .path(COLLECTION_PATH)
                .matchHeader("Accept", "^application/json$", "application/json")
                .matchHeader("Authorization", BEARER_TOKEN_REGEX, AUTHORIZATION_HEADER)
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body
                        .uuid("id", STATUS_REGISTRY_ENTRY_ID)
                        .stringMatcher("statusRegistryUrl", "^https://\\S+$", STATUS_REGISTRY_URL)).build())
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact statusListEntryCreationForbidden(final PactDslWithProvider builder) {
        return builder
                .given("status list entry creation is forbidden for a business entity",
                        Map.of("businessEntityId", BUSINESS_ENTITY_ID.toString()))
                .uponReceiving("POST a status list entry without sufficient permission")
                .method("POST")
                .path(COLLECTION_PATH)
                .matchHeader("Accept", "^application/json$", "application/json")
                .matchHeader("Authorization", BEARER_TOKEN_REGEX, AUTHORIZATION_HEADER)
                .willRespondWith()
                .status(403)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body
                        .stringValue("errorCode", "action_forbidden")
                        .stringType("message", "The business entity is not allowed to create status list entries.")).build())
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "statusListEntryCreated")
    void shouldCreateStatusListEntry(final MockServer mockServer) {
        final var result = buildStatusRegistryClient(mockServer).createStatusListEntry();

        assertThat(result.getId()).isEqualTo(STATUS_REGISTRY_ENTRY_ID);
        assertThat(result.getStatusRegistryUrl()).isEqualTo(STATUS_REGISTRY_URL);
    }

    @Test
    @PactTestFor(pactMethod = "statusListEntryCreationForbidden")
    void shouldMapForbiddenCreationToConfigurationFailure(final MockServer mockServer) {
        final ConfigurationException exception = assertThrows(
                ConfigurationException.class,
                () -> buildStatusRegistryClient(mockServer).createStatusListEntry());

        assertThat(exception)
                .hasMessageContaining(BUSINESS_ENTITY_ID.toString())
                .hasCauseInstanceOf(WebClientResponseException.class);
        assertThat(((WebClientResponseException) exception.getCause()).getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }
}
