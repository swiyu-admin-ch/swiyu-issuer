package ch.admin.bj.swiyu.issuer.service.trustregistry.pact;

import au.com.dius.pact.consumer.MockServer;
import ch.admin.bj.swiyu.core.trust.client.api.TrustProtocol20Api;
import ch.admin.bj.swiyu.core.trust.client.invoker.ApiClient;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.service.enc.CacheMaintenanceService;
import ch.admin.bj.swiyu.issuer.service.trustregistry.TrustStatementCacheService;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class TrustRegistryConsumerPactSupport {

    static final String CONSUMER = "swiyu-issuer";
    static final String PROVIDER = "swiyu-trust-registry";

    static final String ISSUER_DID =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did";
    static final String VCT_ELFA = "https://example.ch/vct/elfa";
    static final String VCT_MDL = "https://example.ch/vct/mdl";

    static final String COMPACT_JWT_REGEX =
            "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$";

    private TrustRegistryConsumerPactSupport() {
    }

    static TrustStatementCacheService buildCacheService(final MockServer mockServer) throws MalformedURLException {
        final ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(mockServer.getUrl());

        final SwiyuProperties.TrustRegistryProperties trustRegistryProperties =
                new SwiyuProperties.TrustRegistryProperties(
                        URI.create(mockServer.getUrl()).toURL(),
                        100,
                        60,
                        300);
        final SwiyuProperties swiyuProperties = mock(SwiyuProperties.class);
        when(swiyuProperties.trustRegistry()).thenReturn(trustRegistryProperties);

        return new TrustStatementCacheService(
                new TrustProtocol20Api(apiClient),
                swiyuProperties,
                Optional.empty(),
                mock(CacheMaintenanceService.class));
    }
}
