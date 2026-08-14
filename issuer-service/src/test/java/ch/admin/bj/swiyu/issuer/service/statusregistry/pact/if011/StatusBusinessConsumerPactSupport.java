package ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if011;

import au.com.dius.pact.consumer.MockServer;
import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;

import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class StatusBusinessConsumerPactSupport {

    static final String CONSUMER = "swiyu-issuer";
    static final String PROVIDER = "swiyu-core-business-service";

    static final UUID BUSINESS_ENTITY_ID = UUID.fromString("8432e1f3-8119-4fb9-a879-190ab2cb9deb");
    static final UUID STATUS_REGISTRY_ENTRY_ID = UUID.fromString("18fa7c77-9dd1-4e20-a147-fb1bec146085");

    static final String COLLECTION_PATH = "/api/v1/status/business-entities/"
            + BUSINESS_ENTITY_ID + "/status-list-entries/";
    static final String ENTRY_PATH = COLLECTION_PATH + STATUS_REGISTRY_ENTRY_ID;
    static final String STATUS_REGISTRY_URL =
            "https://status-registry.example.ch/api/v1/statuslist/" + STATUS_REGISTRY_ENTRY_ID + ".jwt";

    static final String ACCESS_TOKEN = "pact-status-registry-token";
    static final String AUTHORIZATION_HEADER = "Bearer " + ACCESS_TOKEN;
    static final String BEARER_TOKEN_REGEX = "^Bearer\\s+\\S+$";
    static final String JSON_CONTENT_TYPE_REGEX = "^application/json(?:;\\s*charset=[^;]+)?$";
    static final String STATUS_LIST_CONTENT_TYPE_REGEX =
            "^application/statuslist\\+jwt(?:;\\s*charset=[^;]+)?$";
    static final String COMPACT_JWT_REGEX =
            "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$";
    static final String STATUS_LIST_JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0In0."
                    + "eyJpc3MiOiJkaWQ6d2ViOmV4YW1wbGUuY2giLCJzdGF0dXNfbGlzdCI6eyJiaXRzIjoyLCJsc3QiOiJlTnFKIn19."
                    + "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";

    private StatusBusinessConsumerPactSupport() {
    }

    static StatusBusinessApiApi buildStatusBusinessApi(final MockServer mockServer) {
        final ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(mockServer.getUrl());
        apiClient.setBearerToken(ACCESS_TOKEN);
        return new StatusBusinessApiApi(apiClient);
    }

    static StatusRegistryClient buildStatusRegistryClient(final MockServer mockServer) {
        final SwiyuProperties swiyuProperties = mock(SwiyuProperties.class);
        when(swiyuProperties.businessPartnerId()).thenReturn(BUSINESS_ENTITY_ID);

        return new StatusRegistryClient(
                buildStatusBusinessApi(mockServer),
                swiyuProperties,
                mock(UrlRewriteProperties.class),
                mock(ApplicationProperties.class));
    }

    static StatusList statusList() {
        return StatusList.builder()
                .id(UUID.fromString("11111111-1111-4111-8111-111111111111"))
                .uri(STATUS_REGISTRY_URL)
                .build();
    }
}
