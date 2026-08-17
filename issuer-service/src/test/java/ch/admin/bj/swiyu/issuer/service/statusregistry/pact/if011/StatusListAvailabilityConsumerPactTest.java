package ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
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
import static ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011.StatusBusinessConsumerPactSupport.buildStatusBusinessApi;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@PactConsumerTest
@PactTestFor(providerName = PROVIDER, pactVersion = PactSpecVersion.V4)
class StatusListAvailabilityConsumerPactTest {

    private static final String CREATED_AT = "2024-10-29T09:35:16.809Z";

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact firstStatusListEntryPage(final PactDslWithProvider builder) {
        return builder
                .given("one status list entry exists for a business entity",
                        Map.of(
                                "businessEntityId", BUSINESS_ENTITY_ID.toString(),
                                "statusRegistryEntryId", STATUS_REGISTRY_ENTRY_ID.toString(),
                                "page", 0,
                                "size", 1))
                .uponReceiving("GET the first status list entry page for a business entity")
                .method("GET")
                .path(COLLECTION_PATH)
                .query("page=0&size=1")
                .matchHeader("Accept", "^application/json$", "application/json")
                .matchHeader("Authorization", BEARER_TOKEN_REGEX, AUTHORIZATION_HEADER)
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", JSON_CONTENT_TYPE_REGEX, "application/json")
                .body(LambdaDsl.newJsonBody(body -> body
                        .numberType("totalElements", 1L)
                        .integerType("totalPages", 1)
                        .booleanType("first", true)
                        .booleanType("last", true)
                        .integerType("size", 1)
                        .array("content", content -> content.object(entry -> entry
                                .uuid("id", STATUS_REGISTRY_ENTRY_ID)
                                .stringMatcher("createdAt", "^\\d{4}-\\d{2}-\\d{2}T.*Z$", CREATED_AT)
                                .stringMatcher("updatedAt", "^\\d{4}-\\d{2}-\\d{2}T.*Z$", CREATED_AT)))
                        .integerType("number", 0)
                        .integerType("numberOfElements", 1)
                        .booleanType("empty", false)).build())
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact statusListEntryPageUnavailable(final PactDslWithProvider builder) {
        return builder
                .given("status list entry retrieval is unavailable for a business entity",
                        Map.of(
                                "businessEntityId", BUSINESS_ENTITY_ID.toString(),
                                "page", 0,
                                "size", 1))
                .uponReceiving("GET a status list entry page while the service is unavailable")
                .method("GET")
                .path(COLLECTION_PATH)
                .query("page=0&size=1")
                .matchHeader("Accept", "^application/json$", "application/json")
                .matchHeader("Authorization", BEARER_TOKEN_REGEX, AUTHORIZATION_HEADER)
                .willRespondWith()
                .status(503)
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "firstStatusListEntryPage")
    void shouldReadFirstStatusListEntryPage(final MockServer mockServer) {
        final var page = buildStatusBusinessApi(mockServer)
                .getAllStatusListEntries(BUSINESS_ENTITY_ID, 0, 1, null)
                .block();

        assertThat(page).isNotNull();
        assertThat(page.getTotalElements()).isEqualTo(1L);
        assertThat(page.getNumber()).isZero();
        assertThat(page.getContent())
                .singleElement()
                .extracting("id")
                .isEqualTo(STATUS_REGISTRY_ENTRY_ID);
    }

    @Test
    @PactTestFor(pactMethod = "statusListEntryPageUnavailable")
    void shouldExposeUnavailableStatusListEntryPage(final MockServer mockServer) {
        final WebClientResponseException exception = assertThrows(
                WebClientResponseException.class,
                () -> buildStatusBusinessApi(mockServer)
                        .getAllStatusListEntries(BUSINESS_ENTITY_ID, 0, 1, null)
                        .block());

        assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }
}
