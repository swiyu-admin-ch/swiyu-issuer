package ch.admin.bj.swiyu.issuer.service.trustregistry.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonBody;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.annotations.Pact;
import au.com.dius.pact.core.model.matchingrules.MinTypeMatcher;
import au.com.dius.pact.core.model.matchingrules.RegexMatcher;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.COMPACT_JWT_REGEX;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.CONSUMER;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.ISSUER_DID;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.PROVIDER;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.VCT_ELFA;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.VCT_MDL;
import static ch.admin.bj.swiyu.issuer.service.trustregistry.pact.TrustRegistryConsumerPactSupport.buildCacheService;
import static org.assertj.core.api.Assertions.assertThat;

@PactConsumerTest
@PactTestFor(providerName = PROVIDER, pactVersion = PactSpecVersion.V4)
class ProtectedIssuanceAuthorizationTrustStatementConsumerPactTest {

    private static final String PATH = "/api/v2/protected-issuance-authorization-trust-statement/";
    private static final String QUERY = "sub=" + ISSUER_DID + "&filterActive=true";
    private static final String ISSUER_IDENTIFIER = "issuerIdentifier";

    private static final String PIA_TS_ELFA_JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6InN3aXl1LXByb3RlY3RlZC1pc3N1YW5jZS1hdXRob3JpemF0aW9uLXRydXN0LXN0YXRlbWVudCtqd3QiLCJraWQiOiJkaWQ6dGR3OlFtVHJ1c3RTdGF0ZW1lbnRJc3N1ZXI6dHJ1c3QtcmVnaXN0cnkuZXhhbXBsZS5jaDphcGk6djE6ZGlkI2Fzc2VydC1rZXktMDEiLCJwcm9maWxlX3ZlcnNpb24iOiJzd2lzcy1wcm9maWxlLXRydXN0OjIuMC4wIn0."
                    + "eyJqdGkiOiIyMjIyMjIyMi0yMjIyLTQyMjItODIyMi0yMjIyMjIyMjIyMjIiLCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsiaWR4IjoxLCJ1cmkiOiJodHRwczovL3N0YXR1cy5leGFtcGxlLmNoL2FwaS92MS9zdGF0dXNsaXN0LzEuand0In19LCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoiZGlkOnRkdzpRbVl5UVNvMWMxWW03b3JXeExZdkNyelJMWmFkNVp4UThIa0JMeUVFNFJSQkIxOmlkZW50aWZpZXIuYWRtaW4uY2g6YXBpOnYxOmRpZCIsImNhbl9pc3N1ZSI6eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUuY2gvdmN0L2VsZmEiLCJ2Y3RfbmFtZSI6IkVMRkEgY3JlZGVudGlhbCIsInJlYXNvbiI6IkV4YW1wbGUgYXV0aG9yaXphdGlvbiJ9fQ."
                    + "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";

    private static final String PIA_TS_MDL_JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6InN3aXl1LXByb3RlY3RlZC1pc3N1YW5jZS1hdXRob3JpemF0aW9uLXRydXN0LXN0YXRlbWVudCtqd3QiLCJraWQiOiJkaWQ6dGR3OlFtVHJ1c3RTdGF0ZW1lbnRJc3N1ZXI6dHJ1c3QtcmVnaXN0cnkuZXhhbXBsZS5jaDphcGk6djE6ZGlkI2Fzc2VydC1rZXktMDEiLCJwcm9maWxlX3ZlcnNpb24iOiJzd2lzcy1wcm9maWxlLXRydXN0OjIuMC4wIn0."
                    + "eyJqdGkiOiIzMzMzMzMzMy0zMzMzLTQzMzMtODMzMy0zMzMzMzMzMzMzMzMiLCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsiaWR4IjoyLCJ1cmkiOiJodHRwczovL3N0YXR1cy5leGFtcGxlLmNoL2FwaS92MS9zdGF0dXNsaXN0LzEuand0In19LCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoiZGlkOnRkdzpRbVl5UVNvMWMxWW03b3JXeExZdkNyelJMWmFkNVp4UThIa0JMeUVFNFJSQkIxOmlkZW50aWZpZXIuYWRtaW4uY2g6YXBpOnYxOmRpZCIsImNhbl9pc3N1ZSI6eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUuY2gvdmN0L21kbCIsInZjdF9uYW1lIjoibURMIGNyZWRlbnRpYWwiLCJyZWFzb24iOiJFeGFtcGxlIGF1dGhvcml6YXRpb24ifX0."
                    + "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact activeProtectedIssuanceAuthorizationTrustStatements(final PactDslWithProvider builder) {
        return builder
                .given("active Protected Issuance Authorization Trust Statements are registered for an issuer",
                        Map.of(
                                ISSUER_IDENTIFIER, ISSUER_DID,
                                "vctValues", List.of(VCT_ELFA, VCT_MDL)))
                .uponReceiving("GET active Protected Issuance Authorization Trust Statements")
                .method("GET")
                .path(PATH)
                .query(QUERY)
                .matchHeader("Accept", "\\*/\\*", "*/*")
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", "^application/json(?:;\\s*charset=[^;]+)?$", "application/json")
                .body(nonEmptyContentBody())
                .toPact(V4Pact.class);
    }

    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact emptyProtectedIssuanceAuthorizationTrustStatements(final PactDslWithProvider builder) {
        return builder
                .given("no active Protected Issuance Authorization Trust Statement is registered for an issuer",
                        Map.of(ISSUER_IDENTIFIER, ISSUER_DID))
                .uponReceiving("GET active Protected Issuance Authorization Trust Statements when none are registered")
                .method("GET")
                .path(PATH)
                .query(QUERY)
                .matchHeader("Accept", "\\*/\\*", "*/*")
                .willRespondWith()
                .status(200)
                .matchHeader("Content-Type", "^application/json(?:;\\s*charset=[^;]+)?$", "application/json")
                .body(emptyContentBody())
                .toPact(V4Pact.class);
    }

    @Disabled(value = "Changed behavior - must be updated")
    @Pact(consumer = CONSUMER, provider = PROVIDER)
    public V4Pact unavailableProtectedIssuanceAuthorizationTrustStatements(final PactDslWithProvider builder) {
        return builder
                .given("Protected Issuance Authorization Trust Statement retrieval is unavailable",
                        Map.of(ISSUER_IDENTIFIER, ISSUER_DID))
                .uponReceiving("GET Protected Issuance Authorization Trust Statements while retrieval is unavailable")
                .method("GET")
                .path(PATH)
                .query(QUERY)
                .matchHeader("Accept", "\\*/\\*", "*/*")
                .willRespondWith()
                .status(500)
                .toPact(V4Pact.class);
    }

    @Disabled(value="Changed behavior - must be updated")
    @Test
    @PactTestFor(pactMethod = "activeProtectedIssuanceAuthorizationTrustStatements")
    void shouldReturnAllActiveProtectedIssuanceAuthorizationTrustStatements(final MockServer mockServer)
            throws MalformedURLException {
        assertThat(buildCacheService(mockServer)
                .getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .containsExactlyInAnyOrder(PIA_TS_ELFA_JWT, PIA_TS_MDL_JWT);
    }

    @Test
    @PactTestFor(pactMethod = "emptyProtectedIssuanceAuthorizationTrustStatements")
    void shouldReturnEmptyListWhenNoProtectedIssuanceAuthorizationTrustStatementIsRegistered(
            final MockServer mockServer) throws MalformedURLException {
        assertThat(buildCacheService(mockServer)
                .getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .isEmpty();
    }

    @Test
    @PactTestFor(pactMethod = "unavailableProtectedIssuanceAuthorizationTrustStatements")
    void shouldReturnEmptyListWhenProtectedIssuanceAuthorizationTrustStatementRetrievalIsUnavailable(
            final MockServer mockServer) throws MalformedURLException {
        assertThat(buildCacheService(mockServer)
                .getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .isEmpty();
    }

    private static PactDslJsonBody nonEmptyContentBody() {
        final PactDslJsonBody body = new PactDslJsonBody();
        body.array("content")
                .stringValue(PIA_TS_ELFA_JWT)
                .stringValue(PIA_TS_MDL_JWT)
                .closeArray();
        body.getMatchers()
                .addRule("$.content", new MinTypeMatcher(1))
                .addRule("$.content[*]", new RegexMatcher(COMPACT_JWT_REGEX));
        return body;
    }

    private static PactDslJsonBody emptyContentBody() {
        final PactDslJsonBody body = new PactDslJsonBody();
        body.array("content").closeArray();
        return body;
    }
}
