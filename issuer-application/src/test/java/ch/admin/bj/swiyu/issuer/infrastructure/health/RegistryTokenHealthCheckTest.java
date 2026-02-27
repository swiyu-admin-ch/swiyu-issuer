package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.issuer.domain.ecosystem.EcosystemApiType;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenApi;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenSet;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenSetRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegistryTokenHealthCheckTest {

    @Mock
    TokenSetRepository tokenSetRepository;
    @Mock
    TokenSet tokenSet;

    private RegistryTokenHealthCheck registryTokenHealthCheck;

    @BeforeEach
    void setUp() {
        this.registryTokenHealthCheck = new RegistryTokenHealthCheck(tokenSetRepository, Duration.ofMinutes(1));
    }

    @Test
    void performCheck_freshToken_setsUpStatus() throws Exception {
        when(tokenSetRepository.findById(EcosystemApiType.STATUS_REGISTRY)).thenReturn(Optional.of(tokenSet));
        when(tokenSet.getLastRefresh()).thenReturn(Instant.now());

        var builder = Health.unknown();
        registryTokenHealthCheck.performCheck(builder);
        var result = builder.build();

        assertEquals(Status.UP, result.getStatus());
        assertTrue(result.getDetails().containsKey("lastRefresh"));
        assertInstanceOf(Instant.class, result.getDetails().get("lastRefresh"));
        var lastRefresh = (Instant) result.getDetails().get("lastRefresh");
        assertTrue(lastRefresh.isBefore(Instant.now()));
        assertTrue(lastRefresh.isAfter(Instant.now().minus(Duration.ofHours(1))));
    }

    @Test
    void performCheck_expiredToken_setsDownStatus() throws Exception {
        tokenSet.apply(EcosystemApiType.STATUS_REGISTRY, new TokenApi.TokenResponse("foo", "bar"));
        when(tokenSetRepository.findById(EcosystemApiType.STATUS_REGISTRY)).thenReturn(Optional.of(tokenSet));
        when(tokenSet.getLastRefresh()).thenReturn(Instant.now().minus(Duration.ofHours(1)));

        var builder = Health.unknown();
        registryTokenHealthCheck.performCheck(builder);
        var result = builder.build();

        assertEquals(Status.DOWN, result.getStatus());
        assertTrue(result.getDetails().containsKey("lastRefresh"));
        assertInstanceOf(Instant.class, result.getDetails().get("lastRefresh"));
        var lastRefresh = (Instant) result.getDetails().get("lastRefresh");
        assertTrue(lastRefresh.isBefore(Instant.now()));
        assertTrue(lastRefresh.isBefore(Instant.now().minus(Duration.ofHours(1))));
    }

    @Test
    void performCheck_noToken_setsDownStatus() throws Exception {
        when(tokenSetRepository.findById(EcosystemApiType.STATUS_REGISTRY)).thenReturn(Optional.empty());

        var builder = Health.unknown();
        registryTokenHealthCheck.performCheck(builder);
        var result = builder.build();

        assertEquals(Status.DOWN, result.getStatus());
        assertFalse(result.getDetails().containsKey("lastRefresh"));
    }

}
