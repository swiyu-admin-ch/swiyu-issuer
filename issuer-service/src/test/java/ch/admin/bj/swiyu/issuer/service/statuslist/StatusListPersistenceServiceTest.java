package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.UpdateStatusListException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import ch.admin.bj.swiyu.statuslist.TokenStatusList;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link StatusListPersistenceService}.
 * <p>
 * These tests verify the correct update and persistence of status list entries
 * for revoke, suspend, and revalidate operations, as well as the ordering of the local
 * database write and the external registry synchronization.
 */
class StatusListPersistenceServiceTest {

    private StatusListPersistenceService persistenceService;
    private StatusListRepository statusListRepository;
    private StatusListSigningService signingService;
    private StatusRegistryClient statusRegistryClient;
    private ApplicationProperties applicationProperties;
    private StatusListProperties statusListProperties;
    private CredentialOfferStatus offerStatus;

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
    void revoke_shouldReturnStatusListId() throws IOException {
        UUID statusListId = UUID.randomUUID();
        var token = new TokenStatusList(8, 10);
        token.setStatus(1, TokenStatusListBit.REVOKE.getValue());
        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();
        when(statusListRepository.findAllByIdInForUpdate(List.of(statusListId))).thenReturn(List.of(statusList));

        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(1);

        List<UUID> result = persistenceService.revoke(Set.of(offerStatus));
        assertEquals(1, result.size());
        assertEquals(statusListId, result.get(0));
        verify(statusListRepository).saveAllAndFlush(anyList());
    }

    /**
     * Tests that suspending a credential status entry updates the status list and returns the correct status list ID.
     */
    @Test
    void suspend_shouldReturnStatusListId() throws IOException {
        UUID statusListId = UUID.randomUUID();
        TokenStatusList token = new TokenStatusList(8, 10);
        token.setStatus(2, TokenStatusListBit.SUSPEND.getValue());
        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();
        when(statusListRepository.findAllByIdInForUpdate(List.of(statusListId))).thenReturn(List.of(statusList));

        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(2);

        List<UUID> result = persistenceService.suspend(Set.of(offerStatus));
        assertEquals(1, result.size());
        assertEquals(statusListId, result.get(0));
        verify(statusListRepository).saveAllAndFlush(anyList());
    }

    /**
     * Tests that revalidating a credential status entry updates the status list and returns the correct status list ID.
     */
    @Test
    void revalidate_shouldReturnStatusListId() throws IOException {
        UUID statusListId = UUID.randomUUID();
        TokenStatusList token = new TokenStatusList(8, 10);
        token.setStatus(3, TokenStatusListBit.VALID.getValue());
        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();
        when(statusListRepository.findAllByIdInForUpdate(List.of(statusListId))).thenReturn(List.of(statusList));

        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(3);

        List<UUID> result = persistenceService.revalidate(Set.of(offerStatus));
        assertEquals(1, result.size());
        assertEquals(statusListId, result.get(0));
        verify(statusListRepository).saveAllAndFlush(anyList());
    }

    @Test
    void revoke_whenAutomaticSynchronizationEnabled_flushesDatabaseBeforePublishingToRegistry() throws Exception {
        var statusListId = UUID.randomUUID();
        givenStatusListAndOfferStatus(statusListId, 1);
        enableRegistrySynchronization();

        persistenceService.revoke(Set.of(offerStatus));

        InOrder inOrder = inOrder(statusListRepository, statusRegistryClient);
        inOrder.verify(statusListRepository).saveAllAndFlush(anyList());
        inOrder.verify(statusRegistryClient).updateStatusListEntry(any(), anyString());
    }

    @Test
    void revoke_whenDatabaseWriteFails_doesNotPublishToRegistry() throws Exception {
        var statusListId = UUID.randomUUID();
        givenStatusListAndOfferStatus(statusListId, 1);
        enableRegistrySynchronization();
        doThrow(new RuntimeException("database unavailable"))
                .when(statusListRepository).saveAllAndFlush(anyList());

        assertThrows(RuntimeException.class, () -> persistenceService.revoke(Set.of(offerStatus)));

        verifyNoInteractions(statusRegistryClient);
        verify(signingService, never()).buildSignedStatusListJwt(any(), any());
    }

    @Test
    void revoke_whenRegistryUpdateFails_propagatesExceptionSoTheTransactionRollsBack() throws Exception {
        var statusListId = UUID.randomUUID();
        givenStatusListAndOfferStatus(statusListId, 1);
        enableRegistrySynchronization();
        doThrow(new UpdateStatusListException("registry unavailable"))
                .when(statusRegistryClient).updateStatusListEntry(any(), anyString());

        assertThrows(UpdateStatusListException.class, () -> persistenceService.revoke(Set.of(offerStatus)));

        verify(statusListRepository).saveAllAndFlush(anyList());
    }

    @Test
    void revoke_whenAutomaticSynchronizationDisabled_doesNotPublishToRegistry() throws Exception {
        var statusListId = UUID.randomUUID();
        givenStatusListAndOfferStatus(statusListId, 1);

        persistenceService.revoke(Set.of(offerStatus));

        verifyNoInteractions(statusRegistryClient);
        verify(statusListRepository).saveAllAndFlush(anyList());
    }

    private void givenStatusListAndOfferStatus(UUID statusListId, int index) throws IOException {
        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(new TokenStatusList(8, 10).getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();
        when(statusListRepository.findAllByIdInForUpdate(List.of(statusListId))).thenReturn(List.of(statusList));

        offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(index);
    }

    private void enableRegistrySynchronization() {
        when(applicationProperties.isAutomaticStatusListSynchronizationDisabled()).thenReturn(false);
        var jwt = mock(SignedJWT.class);
        when(jwt.serialize()).thenReturn("status-list-jwt");
        when(signingService.buildSignedStatusListJwt(any(), any())).thenReturn(jwt);
    }
}
