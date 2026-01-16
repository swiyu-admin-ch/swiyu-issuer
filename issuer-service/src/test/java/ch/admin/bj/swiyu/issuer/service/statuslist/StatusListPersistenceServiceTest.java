package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link StatusListPersistenceService}.
 * <p>
 * These tests verify the correct update and persistence of status list entries
 * for revoke, suspend, and revalidate operations. The external registry synchronization
 * is disabled for isolation.
 */
class StatusListPersistenceServiceTest {

    private StatusListPersistenceService persistenceService;
    private StatusListRepository statusListRepository;
    private StatusListSigningService signingService;
    private StatusRegistryClient statusRegistryClient;
    private ApplicationProperties applicationProperties;
    private StatusListProperties statusListProperties;

    /**
     * Sets up the test environment by mocking all dependencies and configuring
     * the service under test. Disables automatic status list synchronization.
     */
    @BeforeEach
    void setUp() {
        statusListRepository = mock(StatusListRepository.class);
        signingService = mock(StatusListSigningService.class);
        statusRegistryClient = mock(StatusRegistryClient.class);
        applicationProperties = mock(ApplicationProperties.class);
        statusListProperties = mock(StatusListProperties.class);
        when(statusListProperties.getStatusListSizeLimit()).thenReturn(100 * 1024 * 1024); // 100 MB
        when(applicationProperties.isAutomaticStatusListSynchronizationDisabled()).thenReturn(true); // Disable registry sync in tests
        persistenceService = new StatusListPersistenceService(
                applicationProperties,
                statusListProperties,
                statusListRepository,
                statusRegistryClient,
                signingService
        );
    }

    /**
     * Tests that revoking a credential status entry updates the status list and returns the correct status list ID.
     */
    @Test
    void revoke_shouldReturnStatusListId() {
        UUID statusListId = UUID.randomUUID();
        var token = new TokenStatusListToken(8, 10);
        token.setStatus(1, TokenStatusListBit.REVOKE.getValue());
        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();
        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));
        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(1);
        List<UUID> result = persistenceService.revoke(Set.of(offerStatus));
        assertEquals(1, result.size());
        assertEquals(statusListId, result.get(0));
    }

    /**
     * Tests that suspending a credential status entry updates the status list and returns the correct status list ID.
     */
    @Test
    void suspend_shouldReturnStatusListId() {
        UUID statusListId = UUID.randomUUID();
        TokenStatusListToken token = new TokenStatusListToken(8, 10);
        token.setStatus(2, TokenStatusListBit.SUSPEND.getValue());
        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();
        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));
        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(2);
        List<UUID> result = persistenceService.suspend(Set.of(offerStatus));
        assertEquals(1, result.size());
        assertEquals(statusListId, result.get(0));
    }

    /**
     * Tests that revalidating a credential status entry updates the status list and returns the correct status list ID.
     */
    @Test
    void revalidate_shouldReturnStatusListId() {
        UUID statusListId = UUID.randomUUID();
        TokenStatusListToken token = new TokenStatusListToken(8, 10);
        token.setStatus(3, TokenStatusListBit.VALID.getValue());
        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();
        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));
        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(3);
        List<UUID> result = persistenceService.revalidate(Set.of(offerStatus));
        assertEquals(1, result.size());
        assertEquals(statusListId, result.get(0));
    }
}
