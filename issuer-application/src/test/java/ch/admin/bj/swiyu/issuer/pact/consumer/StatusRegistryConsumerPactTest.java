package ch.admin.bj.swiyu.issuer.pact.consumer;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(PactConsumerTestExt.class)
public class StatusRegistryConsumerPactTest {

    private static final String CONSUMER = "swiyu-issuer";
    private static final String PROVIDER = "swiyu-status-registry";

    private static final UUID BUSINESS_ENTITY_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID STATUS_REGISTRY_ENTRY_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    private static final String STATUS_LIST_JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";

    private static final String PATH =
            "/api/v1/status/business-entities/" + BUSINESS_ENTITY_ID
            + "/status-list-entries/" + STATUS_REGISTRY_ENTRY_ID;

    private final String ERROR_CODE_RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND";

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact pact_updateStatusListEntry_success(final PactDslWithProvider builder) {
        return builder
                .given("A status list entry exists")
                .uponReceiving("PUT valid status list JWT")
                .method("PUT")
                .path(PATH)
                .matchHeader("Content-Type", "application/statuslist\\+jwt.*", "application/statuslist+jwt")
                .body(STATUS_LIST_JWT)
                .willRespondWith()
                .status(200)
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact pact_updateStatusListEntry_notFound(final PactDslWithProvider builder) {
        return builder
                .given("The status list entry does not exist")
                .uponReceiving("PUT status list JWT for non-existing entry")
                .method("PUT")
                .path(PATH)
                .matchHeader("Content-Type", "application/statuslist\\+jwt.*", "application/statuslist+jwt")
                .body(STATUS_LIST_JWT)
                .willRespondWith()
                .status(404)
                .body(LambdaDsl.newJsonBody(body -> {
                    body.stringType("errorCode", ERROR_CODE_RESOURCE_NOT_FOUND);
                    body.stringType("message", "No such status list entry id is known.");
                }).build())
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "pact_updateStatusListEntry_success", pactVersion = PactSpecVersion.V4)
    void test_updateStatusListEntry_when_entryExists_then_success(final MockServer mockServer) {
        final StatusBusinessApiApi api = buildApiClient(mockServer);
        api.updateStatusListEntry(BUSINESS_ENTITY_ID, STATUS_REGISTRY_ENTRY_ID, STATUS_LIST_JWT).block();
    }

    @Test
    @PactTestFor(pactMethod = "pact_updateStatusListEntry_notFound", pactVersion = PactSpecVersion.V4)
    void test_updateStatusListEntry_when_entryDoesNotExist_then_reject404(final MockServer mockServer) {
        final int expectedStatusCode = 404;
        final StatusBusinessApiApi api = buildApiClient(mockServer);

        assertThatThrownBy(() ->
                api.updateStatusListEntry(BUSINESS_ENTITY_ID, STATUS_REGISTRY_ENTRY_ID, STATUS_LIST_JWT).block())
                .isInstanceOf(WebClientResponseException.NotFound.class)
                .satisfies(ex -> {
                    WebClientResponseException.NotFound notFound = (WebClientResponseException.NotFound) ex;
                    assertThat(notFound.getStatusCode().value()).isEqualTo(expectedStatusCode);
                    assertThat(notFound.getResponseBodyAsString()).contains(ERROR_CODE_RESOURCE_NOT_FOUND);
                });
    }

    private StatusBusinessApiApi buildApiClient(final MockServer mockServer) {
        final ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(mockServer.getUrl());
        return new StatusBusinessApiApi(apiClient);
    }
}