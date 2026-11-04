package ch.admin.bj.swiyu.issuer.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactBroker;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerAuth;
import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@Provider("swiyu-issuer")
@PactBroker(url = "${PACT_BROKER_BASE_URL}",
        authentication = @PactBrokerAuth(token = "${PACT_BROKER_TOKEN:}"))
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Import(IssuerManagementPactFixture.class)
class IssuerManagementPactProviderTest {

    @Autowired
    private IssuerManagementPactFixture fixture;
    @LocalServerPort
    private int serverPort;
    @Autowired
    private SwiyuProperties swiyuProperties;
    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;

    private final ApiClient statusRegistryApiClient = Mockito.mock(ApiClient.class);

    @BeforeEach
    void prepareInteraction(final PactVerificationContext context) {
        context.setTarget(new HttpTestTarget("localhost", serverPort));
        fixture.cleanDatabase();
        prepareStatusRegistry();
    }

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void verifyPact(final PactVerificationContext context) {
        context.verifyInteraction();
    }

    @State("status list creation is available")
    Map<String, Object> statusListCreationIsAvailable() {
        return Map.of();
    }

    @State("a status list exists")
    Map<String, Object> aStatusListExists() {
        return fixture.createStatusList();
    }

    @State("a status list exists and can be published")
    Map<String, Object> aStatusListExistsAndCanBePublished() {
        return fixture.createStatusList();
    }

    @State("credential offer creation is available")
    Map<String, Object> credentialOfferCreationIsAvailable() {
        return Map.of();
    }

    @State("an offered credential management exists")
    Map<String, Object> anOfferedCredentialManagementExists() {
        return fixture.createCredentialManagement(false);
    }

    @State("a deferred credential management exists")
    Map<String, Object> aDeferredCredentialManagementExists() {
        return fixture.createCredentialManagement(true);
    }

    private void prepareStatusRegistry() {
        Mockito.reset(statusBusinessApi, statusRegistryApiClient);

        final UUID statusRegistryId = UUID.randomUUID();
        final String statusRegistryUrl =
                "https://status.example.com/api/v1/statuslist/%s.jwt".formatted(statusRegistryId);
        final var creation = new StatusListEntryCreationDto();
        creation.setId(statusRegistryId);
        creation.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(Mono.just(creation));
        when(statusBusinessApi.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());
        when(statusBusinessApi.getApiClient()).thenReturn(statusRegistryApiClient);
        when(statusRegistryApiClient.getBasePath()).thenReturn(statusRegistryUrl);
    }
}
