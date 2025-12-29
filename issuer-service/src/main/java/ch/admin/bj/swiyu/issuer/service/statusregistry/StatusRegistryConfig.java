/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.lock.GlobalLocksType;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenApi;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import java.time.Duration;
import java.time.Instant;

/**
 * Provides api clients for the swiyu ecosystem status registry to the
 * application.
 */
@Slf4j
@Configuration
@AllArgsConstructor
public class StatusRegistryConfig {
    private final SwiyuProperties swiyuProperties;
    private final WebClient webClient;

    @Bean
    public LockConfiguration statusRegistryTokenApiLockConfiguration() {
        return new LockConfiguration(
                Instant.now(),
                GlobalLocksType.STATUS_REGISTRY_TOKEN_MANAGER_TOKEN_REFRESH.getLockId(),
                Duration.ofMinutes(10),
                Duration.ofSeconds(1));
    }

    @Bean
    @Profile("!test")
    public TokenApi statusRegistryTokenApi(RestClient.Builder builder) {
        RestClient restClient = builder
                .baseUrl(swiyuProperties.statusRegistry().tokenUrl().toExternalForm())
                .build();
        var adapter = RestClientAdapter.create(restClient);
        var factory = HttpServiceProxyFactory.builderFor(adapter).build();
        log.info("Initializing status registry token api for {}", swiyuProperties.statusRegistry().tokenUrl().toExternalForm());
        return factory.createClient(TokenApi.class);
    }

    @Bean
    @Profile("test")
    public TokenApi statusRegistryTokenApiForTest() {
        log.info("Initializing status registry token api for {}", swiyuProperties.statusRegistry().tokenUrl().toExternalForm());
        return new TokenApi() {
            @Override
            public TokenApi.TokenResponse getNewToken(String client_id, String client_secret, String grant_type) {
                return new TokenApi.TokenResponse("testAccessToken", "testRefreshToken");
            }

            @Override
            public TokenResponse getNewToken(String client_id, String client_secret, String refresh_token, String grant_type) {
                return new TokenApi.TokenResponse("testAccessToken", "testRefreshToken");
            }
        };
    }

    @Bean
    public ApiClient statusRegistryApiClient(RestClient.Builder builder,
                                             StatusRegistryTokenInterceptor statusRegistryTokenInterceptor,
                                             StatusRegistryContentLengthInterceptor statusRegistryContentLengthInterceptor) {
        builder.requestInterceptor(statusRegistryTokenInterceptor);
        builder.requestInterceptor(statusRegistryContentLengthInterceptor);
        var client = new ApiClient(builder.build());
        client.setBasePath(swiyuProperties.statusRegistry().apiUrl().toExternalForm());
        return client;
    }

    @Bean
    public StatusBusinessApiApi statusBusinessApi(ApiClient statusRegistryApiClient) {
        return new StatusBusinessApiApi(statusRegistryApiClient);
    }
}