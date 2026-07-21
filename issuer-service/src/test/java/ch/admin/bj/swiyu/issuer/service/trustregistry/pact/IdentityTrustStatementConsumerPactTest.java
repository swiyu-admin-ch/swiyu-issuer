package ch.admin.bj.swiyu.issuer.service.trustregistry.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslRootValue;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.COMPACT_JWT_REGEX;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.CONSUMER;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.ISSUER_DID;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.PROVIDER;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.buildCacheService;
import static org.assertj.core.api.Assertions.assertThat;

@PactConsumerTest
@PactTestFor(providerName = PROVIDER, pactVersion = PactSpecVersion.V4)
class IdentityTrustStatementConsumerPactTest {

    private static final String PATH = "/api/v2/identity-trust-statement/"
            + URLEncoder.encode(ISSUER_DID, StandardCharsets.UTF_8);
    private static final String ACTOR_IDENTIFIER = "actorIdentifier";

    private static final String ID_TS_JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6InN3aXl1LWlkZW50aXR5LXRydXN0LXN0YXRlbWVudCtqd3QiLCJraWQiOiJkaWQ6dGR3OlFtVHJ1c3RTdGF0ZW1lbnRJc3N1ZXI6dHJ1c3QtcmVnaXN0cnkuZXhhbXBsZS5jaDphcGk6djE6ZGlkI2Fzc2VydC1rZXktMDEiLCJwcm9maWxlX3ZlcnNpb24iOiJzd2lzcy1wcm9maWxlLXRydXN0OjIuMC4wIn0."
                    + "eyJqdGkiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6NDEwMjQ0NDgwMCwic3RhdHVzIjp7InN0YXR1c19saXN0Ijp7ImlkeCI6MCwidXJpIjoiaHR0cHM6Ly9zdGF0dXMuZXhhbXBsZS5jaC9hcGkvdjEvc3RhdHVzbGlzdC8xLmp3dCJ9fSwic3ViIjoiZGlkOnRkdzpRbVl5UVNvMWMxWW03b3JXeExZdkNyelJMWmFkNVp4UThIa0JMeUVFNFJSQkIxOmlkZW50aWZpZXIuYWRtaW4uY2g6YXBpOnYxOmRpZCIsImVudGl0eV9uYW1lIjoiRXhhbXBsZSBQdWJsaWMgSXNzdWVyIiwiaXNfc3RhdGVfYWN0b3IiOnRydWUsInJlZ2lzdHJ5X2lkcyI6W3sidHlwZSI6IlVJRCIsInZhbHVlIjoiQ0hFLTEyMy40NTYuNzg5In1dfQ."
                    + "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact activeIdentityTrustStatement(final PactDslWithProvider builder) {
        return builder
                .given("an active Identity Trust Statement is registered for an actor",
                        Map.of(ACTOR_IDENTIFIER, ISSUER_DID))
                .uponReceiving("GET an active Identity Trust Statement")
                .method("GET")
                .path(PATH)
                .matchHeader("Accept", "\\*/\\*", "*/*")
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", "^text/plain(?:;\\s*charset=[^;]+)?$", "text/plain")
                .body(PactDslRootValue.stringMatcher(COMPACT_JWT_REGEX, ID_TS_JWT))
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact missingIdentityTrustStatement(final PactDslWithProvider builder) {
        return builder
                .given("no Identity Trust Statement is registered for an actor",
                        Map.of(ACTOR_IDENTIFIER, ISSUER_DID))
                .uponReceiving("GET a missing Identity Trust Statement")
                .method("GET")
                .path(PATH)
                .matchHeader("Accept", "\\*/\\*", "*/*")
                .willRespondWith()
                .status(404)
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact unavailableIdentityTrustStatement(final PactDslWithProvider builder) {
        return builder
                .given("Identity Trust Statement retrieval is unavailable",
                        Map.of(ACTOR_IDENTIFIER, ISSUER_DID))
                .uponReceiving("GET an Identity Trust Statement while retrieval is unavailable")
                .method("GET")
                .path(PATH)
                .matchHeader("Accept", "\\*/\\*", "*/*")
                .willRespondWith()
                .status(500)
                .toPact(V4Pact.class);
    }

    @Test
    @PactTestFor(pactMethod = "activeIdentityTrustStatement")
    void shouldReturnActiveIdentityTrustStatement(final MockServer mockServer) throws MalformedURLException {
        assertThat(buildCacheService(mockServer).getIdentityTrustStatement(ISSUER_DID))
                .isEqualTo(ID_TS_JWT);
    }

    @Test
    @PactTestFor(pactMethod = "missingIdentityTrustStatement")
    void shouldReturnNullWhenIdentityTrustStatementIsMissing(final MockServer mockServer)
            throws MalformedURLException {
        assertThat(buildCacheService(mockServer).getIdentityTrustStatement(ISSUER_DID))
                .isNull();
    }

    @Test
    @PactTestFor(pactMethod = "unavailableIdentityTrustStatement")
    void shouldReturnNullWhenIdentityTrustStatementRetrievalIsUnavailable(final MockServer mockServer)
            throws MalformedURLException {
        assertThat(buildCacheService(mockServer).getIdentityTrustStatement(ISSUER_DID))
                .isNull();
    }
}
