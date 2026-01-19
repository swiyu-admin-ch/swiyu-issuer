package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.EcosystemApiType;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenApi;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenSet;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenSetRepository;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import net.javacrumbs.shedlock.core.SimpleLock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.domain.ecosystem.EcosystemApiType.STATUS_REGISTRY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class StatusRegistryTokenServiceTest {

    @Mock
    private SwiyuProperties swiyuProperties;

    @Mock
    private TokenSetRepository tokenSetRepository;

    @Mock
    private LockingTaskExecutor lockingTaskExecutor;

    @Mock
    private LockConfiguration statusRegistryTokenApiLockConfiguration;

    @Mock
    private TokenApi statusRegistryTokenApi;

    @Mock
    private SwiyuProperties.RegistryProperties registryProperties;

    private StatusRegistryTokenService service;

    private AutoCloseable mocks;

    @BeforeEach
    void setUp() throws MalformedURLException {
        mocks = MockitoAnnotations.openMocks(this);

        // Setup default mock behavior for SwiyuProperties
        when(swiyuProperties.statusRegistry()).thenReturn(registryProperties);
        when(registryProperties.customerKey()).thenReturn("test-customer-key");
        when(registryProperties.customerSecret()).thenReturn("test-customer-secret");
        when(registryProperties.enableRefreshTokenFlow()).thenReturn(true);
        when(registryProperties.bootstrapRefreshToken()).thenReturn("bootstrap-refresh-token");
        when(registryProperties.apiUrl()).thenReturn(new URL("https://api.example.com"));
        when(registryProperties.tokenUrl()).thenReturn(new URL("https://token.example.com"));
        when(registryProperties.tokenRefreshInterval()).thenReturn(Duration.ofMinutes(30));
        when(swiyuProperties.businessPartnerId()).thenReturn(UUID.randomUUID());

        service = new StatusRegistryTokenService(
                swiyuProperties,
                tokenSetRepository,
                lockingTaskExecutor,
                statusRegistryTokenApiLockConfiguration,
                statusRegistryTokenApi
        );
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void getAccessToken_whenTokenExists_thenReturnsToken() {
        // Given
        TokenSet tokenSet = new TokenSet();
        TokenApi.TokenResponse tokenResponse = new TokenApi.TokenResponse("access-token-123", "refresh-token-123");
        tokenSet.apply(STATUS_REGISTRY, tokenResponse);

        when(tokenSetRepository.findById(STATUS_REGISTRY)).thenReturn(Optional.of(tokenSet));

        // When
        String accessToken = service.getAccessToken();

        // Then
        assertThat(accessToken).isEqualTo("access-token-123");
        verify(tokenSetRepository).findById(STATUS_REGISTRY);
    }

    @Test
    void getAccessToken_whenTokenDoesNotExist_thenThrowsIllegalStateException() {
        // Given
        when(tokenSetRepository.findById(STATUS_REGISTRY)).thenReturn(Optional.empty());

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> service.getAccessToken());
        assertThat(exception.getMessage()).contains("Failed to lookup authorization token");
        verify(tokenSetRepository).findById(STATUS_REGISTRY);
    }

    @Test
    void forceRefreshAccessToken_whenExecutionFails_thenThrowsJsonException() throws Throwable {
        // Given
        when(lockingTaskExecutor.executeWithLock(any(LockingTaskExecutor.TaskWithResult.class), eq(statusRegistryTokenApiLockConfiguration)))
                .thenThrow(new RuntimeException("Lock execution failed"));

        // When & Then
        assertThrows(JsonException.class, () -> service.forceRefreshAccessToken());
        verify(lockingTaskExecutor).executeWithLock(any(LockingTaskExecutor.TaskWithResult.class), eq(statusRegistryTokenApiLockConfiguration));
    }

    @Test
    void requestNewTokenSet_withExistingDbToken_thenRefreshesUsingDbToken() {
        // Given
        TokenSet existingTokenSet = new TokenSet();
        TokenApi.TokenResponse existingResponse = new TokenApi.TokenResponse("old-access", "old-refresh");
        existingTokenSet.apply(STATUS_REGISTRY, existingResponse);

        TokenApi.TokenResponse newResponse = new TokenApi.TokenResponse("new-access", "new-refresh");

        when(tokenSetRepository.findById(STATUS_REGISTRY)).thenReturn(Optional.of(existingTokenSet));
        when(statusRegistryTokenApi.getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("old-refresh"),
                eq("refresh_token")
        )).thenReturn(newResponse);
        when(tokenSetRepository.save(any(TokenSet.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        TokenSet result;
        try (MockedStatic<LockAssert> lockAssert = Mockito.mockStatic(LockAssert.class)) {
            lockAssert.when(LockAssert::assertLocked).then(invocation -> null);
            result = service.requestNewTokenSet();
        }

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getAccessToken()).isEqualTo("new-access");
        assertThat(result.getRefreshToken()).isEqualTo("new-refresh");
        verify(statusRegistryTokenApi).getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("old-refresh"),
                eq("refresh_token")
        );
        verify(tokenSetRepository).save(any(TokenSet.class));
    }

    @Test
    void requestNewTokenSet_withNoDbToken_thenUsesBootstrapToken() {
        // Given
        TokenApi.TokenResponse newResponse = new TokenApi.TokenResponse("bootstrap-access", "bootstrap-refresh");

        when(tokenSetRepository.findById(STATUS_REGISTRY)).thenReturn(Optional.empty());
        when(statusRegistryTokenApi.getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("bootstrap-refresh-token"),
                eq("refresh_token")
        )).thenReturn(newResponse);
        when(tokenSetRepository.save(any(TokenSet.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        TokenSet result;
        try (MockedStatic<LockAssert> lockAssert = Mockito.mockStatic(LockAssert.class)) {
            lockAssert.when(LockAssert::assertLocked).then(invocation -> null);
            result = service.requestNewTokenSet();
        }

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getAccessToken()).isEqualTo("bootstrap-access");
        assertThat(result.getRefreshToken()).isEqualTo("bootstrap-refresh");
        verify(statusRegistryTokenApi).getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("bootstrap-refresh-token"),
                eq("refresh_token")
        );
        verify(tokenSetRepository).save(any(TokenSet.class));
    }

    @Test
    void requestNewTokenSet_withDbTokenFailure_thenFallsBackToBootstrap() {
        // Given
        TokenSet existingTokenSet = new TokenSet();
        TokenApi.TokenResponse existingResponse = new TokenApi.TokenResponse("old-access", "old-refresh");
        existingTokenSet.apply(STATUS_REGISTRY, existingResponse);

        TokenApi.TokenResponse bootstrapResponse = new TokenApi.TokenResponse("bootstrap-access", "bootstrap-refresh");

        when(tokenSetRepository.findById(STATUS_REGISTRY)).thenReturn(Optional.of(existingTokenSet));
        when(statusRegistryTokenApi.getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("old-refresh"),
                eq("refresh_token")
        )).thenThrow(new RuntimeException("DB token expired"));
        when(statusRegistryTokenApi.getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("bootstrap-refresh-token"),
                eq("refresh_token")
        )).thenReturn(bootstrapResponse);
        when(tokenSetRepository.save(any(TokenSet.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        TokenSet result;
        try (MockedStatic<LockAssert> lockAssert = Mockito.mockStatic(LockAssert.class)) {
            lockAssert.when(LockAssert::assertLocked).then(invocation -> null);
            result = service.requestNewTokenSet();
        }

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getAccessToken()).isEqualTo("bootstrap-access");
        assertThat(result.getRefreshToken()).isEqualTo("bootstrap-refresh");
        verify(statusRegistryTokenApi).getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("old-refresh"),
                eq("refresh_token")
        );
        verify(statusRegistryTokenApi).getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("bootstrap-refresh-token"),
                eq("refresh_token")
        );
        verify(tokenSetRepository).save(any(TokenSet.class));
    }

    @Test
    void requestNewTokenSet_withRefreshTokenFlowDisabled_thenUsesClientCredentials() {
        // Given
        when(registryProperties.enableRefreshTokenFlow()).thenReturn(false);

        TokenApi.TokenResponse newResponse = new TokenApi.TokenResponse("client-credentials-access", null);

        when(tokenSetRepository.findById(STATUS_REGISTRY)).thenReturn(Optional.empty());
        when(statusRegistryTokenApi.getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("client_credentials")
        )).thenReturn(newResponse);
        when(tokenSetRepository.save(any(TokenSet.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        TokenSet result;
        try (MockedStatic<LockAssert> lockAssert = Mockito.mockStatic(LockAssert.class)) {
            lockAssert.when(LockAssert::assertLocked).then(invocation -> null);
            result = service.requestNewTokenSet();
        }

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getAccessToken()).isEqualTo("client-credentials-access");
        verify(statusRegistryTokenApi).getNewToken(
                eq("test-customer-key"),
                eq("test-customer-secret"),
                eq("client_credentials")
        );
        verify(tokenSetRepository).save(any(TokenSet.class));
    }

    @Test
    void bootstrapTokenSetRefresh_shouldExecuteWithLock() {
        // Given
        doAnswer(invocation -> {
            Runnable runnable = invocation.getArgument(0);
            runnable.run();
            return null;
        }).when(lockingTaskExecutor).executeWithLock(any(Runnable.class), eq(statusRegistryTokenApiLockConfiguration));

        TokenApi.TokenResponse newResponse = new TokenApi.TokenResponse("bootstrap-access", "bootstrap-refresh");
        when(tokenSetRepository.findById(STATUS_REGISTRY)).thenReturn(Optional.empty());
        when(statusRegistryTokenApi.getNewToken(any(), any(), any(), any())).thenReturn(newResponse);
        when(tokenSetRepository.save(any(TokenSet.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        try (MockedStatic<LockAssert> lockAssert = Mockito.mockStatic(LockAssert.class)) {
            lockAssert.when(LockAssert::assertLocked).then(invocation -> null);
            service.bootstrapTokenSetRefresh();
        }

        // Then
        verify(lockingTaskExecutor).executeWithLock(any(Runnable.class), eq(statusRegistryTokenApiLockConfiguration));
    }

    @Test
    void bootstrapTokenSetRefresh_whenFails_shouldLogError() {
        // Given
        doAnswer(invocation -> {
            Runnable runnable = invocation.getArgument(0);
            runnable.run();
            return null;
        }).when(lockingTaskExecutor).executeWithLock(any(Runnable.class), eq(statusRegistryTokenApiLockConfiguration));

        when(tokenSetRepository.findById(STATUS_REGISTRY)).thenReturn(Optional.empty());
        when(statusRegistryTokenApi.getNewToken(any(), any(), any(), any()))
                .thenThrow(new RuntimeException("Bootstrap failed"));

        // When
        try (MockedStatic<LockAssert> lockAssert = Mockito.mockStatic(LockAssert.class)) {
            lockAssert.when(LockAssert::assertLocked).then(invocation -> null);
            // Should not throw, just log error
            service.bootstrapTokenSetRefresh();
        }

        // Then
        verify(lockingTaskExecutor).executeWithLock(any(Runnable.class), eq(statusRegistryTokenApiLockConfiguration));
    }
}

