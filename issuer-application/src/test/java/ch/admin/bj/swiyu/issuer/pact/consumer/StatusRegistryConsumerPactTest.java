package ch.admin.bj.swiyu.issuer.pact.consumer;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.dsl.LambdaDsl;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import au.com.dius.pact.core.model.PactSpecVersion;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(PactConsumerTestExt.class)
public class StatusRegistryConsumerPactTest {

    private static final String CONSUMER = "swiyu-issuer";
    private static final String PROVIDER = "swiyu-status-registry";

    private static final String DATASTORE_ID = "11111111-1111-1111-1111-111111111111";
    private static final String JWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
    private static final String PATH = "/api/v1/statuslist/" + DATASTORE_ID + ".jwt";

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact publishStatusList_success(final PactDslWithProvider builder) {
        return builder
                .given("a datastore entry exists and is editable")
                .uponReceiving("PUT valid status list JWT")
                .method("PUT")
                .path(PATH)
                .matchHeader("Content-Type", "application/jwt", "application/jwt")
                .body(JWT)
                .willRespondWith()
                .status(200)
                .body(LambdaDsl.newJsonBody(o -> {
                    o.stringType("id");
                    o.stringType("status");
                }).build())
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "publishStatusList_success", pactVersion = PactSpecVersion.V4)
    void test_success(final MockServer mockServer) {
        final ResponseEntity<String> response = callProvider(mockServer);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact publishStatusList_notFound(final PactDslWithProvider builder) {
        return builder
                .given("The datastore entry does not exist")
                .uponReceiving("PUT status list JWT for non-existing entry")
                .method("PUT")
                .path(PATH)
                .matchHeader("Content-Type", "application/jwt", "application/jwt")
                .body(JWT)
                .willRespondWith()
                .status(404)
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "publishStatusList_notFound", pactVersion = PactSpecVersion.V4)
    void test_notFound(final MockServer mockServer) {
        final ResponseEntity<String> response = callProvider(mockServer);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact publishStatusList_notEditable(final PactDslWithProvider builder) {
        return builder
                .given("The datastore entry exists but cannot be edited")
                .uponReceiving("PUT status list JWT but entry is locked")
                .method("PUT")
                .path(PATH)
                .matchHeader("Content-Type", "application/jwt", "application/jwt")
                .body(JWT)
                .willRespondWith()
                .status(425)
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "publishStatusList_notEditable", pactVersion = PactSpecVersion.V4)
    void test_notEditable(final MockServer mockServer) {
        final ResponseEntity<String> response = callProvider(mockServer);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.valueOf(425));
    }

    private ResponseEntity<String> callProvider(final MockServer mockServer) {

        final RestTemplate restTemplate = new RestTemplate();

        restTemplate.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }
        });

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.valueOf("application/jwt"));

        final HttpEntity<String> request = new HttpEntity<>(JWT, headers);

        return restTemplate.exchange(
                mockServer.getUrl() + PATH,
                HttpMethod.PUT,
                request,
                String.class
        );
    }
}