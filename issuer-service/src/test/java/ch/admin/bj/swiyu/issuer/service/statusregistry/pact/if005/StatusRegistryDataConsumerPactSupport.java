package ch.admin.bj.swiyu.issuer.service.statusregistry.pact.if005;

import au.com.dius.pact.consumer.MockServer;
import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.mock;

final class StatusRegistryDataConsumerPactSupport {

    static final String CONSUMER = "swiyu-issuer";
    static final String PROVIDER = "swiyu-status-registry";

    static final UUID STATUS_LIST_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    static final String STATUS_LIST_PATH = "/api/v1/statuslist/" + STATUS_LIST_ID + ".jwt";
    static final String STATUS_LIST_URI = "https://status-registry.example.ch" + STATUS_LIST_PATH;

    static final String COMPACT_JWT_REGEX =
            "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$";
    static final String STATUS_LIST_JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0In0"
                    + ".eyJpc3MiOiJodHRwczovL3N0YXR1cy1yZWdpc3RyeS5leGFtcGxlLmNoIn0"
                    + ".c2lnbmF0dXJl";

    private StatusRegistryDataConsumerPactSupport() {
    }

    static StatusRegistryClient buildStatusRegistryClient(final MockServer mockServer) {
        final ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(mockServer.getUrl());

        final UrlRewriteProperties urlRewriteProperties = new UrlRewriteProperties();
        urlRewriteProperties.setUrlMappings(Map.of(
                "https://status-registry.example.ch",
                mockServer.getUrl()));

        final ApplicationProperties applicationProperties = new ApplicationProperties();
        applicationProperties.setAcceptedRegistryHosts(List.of(URI.create(mockServer.getUrl()).getHost()));

        return new StatusRegistryClient(
                new StatusBusinessApiApi(apiClient),
                mock(SwiyuProperties.class),
                urlRewriteProperties,
                applicationProperties);
    }
}
