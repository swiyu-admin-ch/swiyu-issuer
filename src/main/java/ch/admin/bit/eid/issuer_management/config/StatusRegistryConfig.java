package ch.admin.bit.eid.issuer_management.config;

import ch.admin.bit.eid.issuer_management.domain.ecosystem.StatusRegistryTokenInterceptor;
import ch.admin.bit.eid.issuer_management.domain.ecosystem.TokenApi;
import ch.admin.bit.eid.issuer_management.enums.GlobalLocksEnum;
import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import lombok.AllArgsConstructor;
import net.javacrumbs.shedlock.core.LockConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import java.time.Duration;
import java.time.Instant;

/**
 * Provides api clients for the swiyu ecosystem status registry to the application.
 */
@Configuration
@AllArgsConstructor
public class StatusRegistryConfig {
    private final SwiyuProperties swiyuProperties;

    @Bean
    public LockConfiguration statusRegistryTokenApiLockConfiguration() {
        return new LockConfiguration(
                Instant.now(),
                GlobalLocksEnum.STATUS_REGISTRY_TOKEN_MANAGER_TOKEN_REFRESH.getLockId(),
                Duration.ofMinutes(10),
                Duration.ofSeconds(1)
        );
    }

    @Bean
    public TokenApi statusRegistryTokenApi(RestClient.Builder builder) {
        RestClient restClient = builder
                .baseUrl(swiyuProperties.statusRegistry().tokenUrl().toExternalForm())
                .build();
        var adapter = RestClientAdapter.create(restClient);
        var factory = HttpServiceProxyFactory.builderFor(adapter).build();
        return factory.createClient(TokenApi.class);
    }

    @Bean
    public ApiClient statusRegistryApiClient(RestClient.Builder builder, StatusRegistryTokenInterceptor statusRegistryTokenInterceptor) {
        builder.requestInterceptor(statusRegistryTokenInterceptor);
        var client = new ApiClient(builder.build());
        client.setBasePath(swiyuProperties.statusRegistry().apiUrl().toExternalForm());
        return client;
    }

    @Bean
    public StatusBusinessApiApi statusBusinessApi(ApiClient statusRegistryApiClient) {
        return new StatusBusinessApiApi(statusRegistryApiClient);
    }

}
