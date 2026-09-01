package ch.admin.bj.swiyu.issuer.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactFolder;
import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Provider("swiyu-issuer")
@PactFolder
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class IssuerManagementPactProviderTest {

    private static final String CREDENTIALS_PATH = "/management/api/credentials";
    private static final String STATUS_LIST_PATH = "/management/api/status-list";

    @Autowired
    private MockMvc mockMvc;
    @LocalServerPort
    private int serverPort;
    @Autowired
    private SwiyuProperties swiyuProperties;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;

    private final ApiClient statusRegistryApiClient = Mockito.mock(ApiClient.class);

    @BeforeEach
    void prepareInteraction(final PactVerificationContext context) {
        // Pact 4.7.5's MockMvc target is not binary-compatible with Spring 7; state setup still uses MockMvc.
        context.setTarget(new HttpTestTarget("localhost", serverPort));
        cleanDatabase();
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
    Map<String, Object> aStatusListExists() throws Exception {
        return createStatusList();
    }

    @State("a status list exists and can be published")
    Map<String, Object> aStatusListExistsAndCanBePublished() throws Exception {
        return createStatusList();
    }

    @State("credential offer creation is available")
    Map<String, Object> credentialOfferCreationIsAvailable() {
        return Map.of();
    }

    @State("an offered credential management exists")
    Map<String, Object> anOfferedCredentialManagementExists() throws Exception {
        return createCredentialManagement(false, false);
    }

    @State("a deferred credential management exists")
    Map<String, Object> aDeferredCredentialManagementExists() throws Exception {
        return createCredentialManagement(true, true);
    }

    private Map<String, Object> createStatusList() throws Exception {
        final MvcResult result = mockMvc.perform(post(STATUS_LIST_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "maxLength": 1000,
                                  "config": {
                                    "bits": 2
                                  }
                                }
                                """))
                .andExpect(status().isOk())
                .andReturn();

        final String statusListId = JsonPath.read(result.getResponse().getContentAsString(), "$.id");
        return Map.of("statusListId", statusListId);
    }

    private Map<String, Object> createCredentialManagement(final boolean deferred,
                                                           final boolean markAsDeferred) throws Exception {
        final MvcResult result = mockMvc.perform(post(CREDENTIALS_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentialCreationPayload(deferred)))
                .andExpect(status().isOk())
                .andReturn();

        final String managementId = JsonPath.read(result.getResponse().getContentAsString(), "$.management_id");
        final String offerId = JsonPath.read(result.getResponse().getContentAsString(), "$.offer_id");

        if (markAsDeferred) {
            final var offer = credentialOfferRepository.findById(UUID.fromString(offerId)).orElseThrow();
            offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.DEFERRED);
            credentialOfferRepository.saveAndFlush(offer);
        }

        return Map.of(
                "managementId", managementId,
                "offerId", offerId);
    }

    private String credentialCreationPayload(final boolean deferred) {
        return """
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": {
                    "firstName": "John",
                    "lastName": "Doe",
                    "dateOfBirth": "2000-01-01"
                  },
                  "credential_metadata": {
                    "deferred": %s
                  },
                  "offer_validity_seconds": 86400,
                  "status_lists": []
                }
                """.formatted(deferred);
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

    private void cleanDatabase() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        credentialManagementRepository.deleteAll();
        statusListRepository.deleteAll();
    }
}
