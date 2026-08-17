package ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import au.com.dius.pact.consumer.dsl.PactDslRootValue;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import ch.admin.bj.swiyu.issuer.common.exception.UpdateStatusListException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.AUTHORIZATION_HEADER;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.BEARER_TOKEN_REGEX;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.BUSINESS_ENTITY_ID;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.COMPACT_JWT_REGEX;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.CONSUMER;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.ENTRY_PATH;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.JSON_CONTENT_TYPE_REGEX;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.PROVIDER;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.STATUS_LIST_CONTENT_TYPE_REGEX;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.STATUS_LIST_JWT;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.STATUS_REGISTRY_ENTRY_ID;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.buildStatusRegistryClient;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.statusList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;

@PactConsumerTest
@PactTestFor(providerName = PROVIDER, pactVersion = PactSpecVersion.V4)
class StatusListEntryUpdateConsumerPactTest {

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact statusListEntryUpdated(final PactDslWithProvider builder) {
        return builder
                .given("a status list entry belongs to a business entity",
                        Map.of(
                                "businessEntityId", BUSINESS_ENTITY_ID.toString(),
                                "statusRegistryEntryId", STATUS_REGISTRY_ENTRY_ID.toString()))
                .uponReceiving("PUT a compact status list JWT into an existing entry")
                .method("PUT")
                .path(ENTRY_PATH)
                .matchHeader("Accept", "^application/json$", "application/json")
                .matchHeader("Authorization", BEARER_TOKEN_REGEX, AUTHORIZATION_HEADER)
                .matchHeader("Content-Type", STATUS_LIST_CONTENT_TYPE_REGEX, "application/statuslist+jwt")
                .body(PactDslRootValue.stringMatcher(COMPACT_JWT_REGEX, STATUS_LIST_JWT))
                .willRespondWith()
                .status(200)
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact statusListEntryMissing(final PactDslWithProvider builder) {
        return builder
                .given("no status list entry exists for a business entity",
                        Map.of(
                                "businessEntityId", BUSINESS_ENTITY_ID.toString(),
                                "statusRegistryEntryId", STATUS_REGISTRY_ENTRY_ID.toString()))
                .uponReceiving("PUT a compact status list JWT into a missing entry")
                .method("PUT")
                .path(ENTRY_PATH)
                .matchHeader("Accept", "^application/json$", "application/json")
                .matchHeader("Authorization", BEARER_TOKEN_REGEX, AUTHORIZATION_HEADER)
                .matchHeader("Content-Type", STATUS_LIST_CONTENT_TYPE_REGEX, "application/statuslist+jwt")
                .body(PactDslRootValue.stringMatcher(COMPACT_JWT_REGEX, STATUS_LIST_JWT))
                .willRespondWith()
                .status(404)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body
                        .stringValue("errorCode", "resource_not_found")
                        .stringType("message", "The status list entry does not exist.")).build())
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "statusListEntryUpdated")
    void shouldUpdateStatusListEntry(final MockServer mockServer) {
        assertThatCode(() -> buildStatusRegistryClient(mockServer).updateStatusListEntry(statusList(), STATUS_LIST_JWT))
                .doesNotThrowAnyException();
    }

    @Test
    @PactTestFor(pactMethod = "statusListEntryMissing")
    void shouldFailSafelyWhenStatusListEntryIsMissing(final MockServer mockServer) {
        final UpdateStatusListException exception = assertThrows(
                UpdateStatusListException.class,
                () -> buildStatusRegistryClient(mockServer).updateStatusListEntry(statusList(), STATUS_LIST_JWT));

        assertThat(exception)
                .hasMessage("Failed to update status list.")
                .hasCauseInstanceOf(WebClientResponseException.class);
        assertThat(((WebClientResponseException) exception.getCause()).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }
}
