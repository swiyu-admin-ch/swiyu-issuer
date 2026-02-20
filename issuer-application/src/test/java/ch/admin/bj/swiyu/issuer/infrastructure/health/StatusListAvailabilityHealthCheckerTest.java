package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.PageStatusListEntryDto;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StatusListAvailabilityHealthCheckerTest {

    @Mock
    StatusBusinessApiApi statusBusinessApi;
    @Mock
    SwiyuProperties swiyuProperties;

    StatusListAvailabilityHealthChecker registryHealthCheck;

    @BeforeEach
    void setUp() {
        this.registryHealthCheck = new StatusListAvailabilityHealthChecker(statusBusinessApi, swiyuProperties);
    }

    @Test
    void performCheck_registryReachable_setsUpStatus() {
        var uuid = UUID.randomUUID();
        when(swiyuProperties.businessPartnerId()).thenReturn(uuid);
        when(statusBusinessApi.getAllStatusListEntries(any(), any(), any(), any())).thenReturn(Mono.just(new PageStatusListEntryDto()));

        var builder = Health.unknown();
        assertDoesNotThrow(() -> this.registryHealthCheck.performCheck(builder));
        var result = builder.build();

        assertEquals(Status.UP, result.getStatus());
        assertTrue(result.getDetails().containsKey("partnerId"));
        assertEquals(uuid, (UUID) result.getDetails().get("partnerId"));
    }

    @Test
    void performCheck_registryUnreachable_setsDownStatus() {
        var uuid = UUID.randomUUID();
        when(swiyuProperties.businessPartnerId()).thenReturn(uuid);
        when(statusBusinessApi.getAllStatusListEntries(any(), any(), any(), any())).thenThrow(new WebClientResponseException(400, "test", new HttpHeaders(), new byte[0], Charset.defaultCharset()));

        var builder = Health.unknown();
        assertDoesNotThrow(() -> this.registryHealthCheck.performCheck(builder));
        var result = builder.build();

        assertEquals(Status.DOWN, result.getStatus());
        assertTrue(result.getDetails().containsKey("partnerId"));
        assertEquals(uuid, (UUID) result.getDetails().get("partnerId"));
    }

    @Test
    void performCheck_unexpectedError_doesNotSetStatus() {
        var uuid = UUID.randomUUID();
        when(swiyuProperties.businessPartnerId()).thenReturn(uuid);
        when(statusBusinessApi.getAllStatusListEntries(any(), any(), any(), any())).thenThrow(new RuntimeException("test"));

        var builder = Health.unknown();
        assertThrows(RuntimeException.class, () -> this.registryHealthCheck.performCheck(builder));
        var result = builder.build();

        assertEquals(Status.UNKNOWN, result.getStatus());
    }
}