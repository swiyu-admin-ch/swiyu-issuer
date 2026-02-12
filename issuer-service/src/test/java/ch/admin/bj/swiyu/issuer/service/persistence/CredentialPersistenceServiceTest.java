package ch.admin.bj.swiyu.issuer.service.persistence;

import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialPersistenceServiceTest {

    @Mock
    private CredentialOfferRepository credentialOfferRepository;

    @Mock
    private CredentialManagementRepository credentialManagementRepository;

    @Mock
    private CredentialOfferStatusRepository credentialOfferStatusRepository;

    @Mock
    private AvailableStatusListIndexRepository availableStatusListIndexRepository;

    private CredentialPersistenceService persistenceService;

    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        persistenceService = new CredentialPersistenceService(
                credentialOfferRepository,
                credentialManagementRepository,
                credentialOfferStatusRepository,
                availableStatusListIndexRepository
        );
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    /**
     * Verifies that a credential offer is forwarded to the repository and the repository result is returned.
     */
    @Test
    void saveCredentialOffer_shouldSaveAndReturn() {
        var offer = CredentialOffer.builder().id(UUID.randomUUID()).build();
        when(credentialOfferRepository.save(offer)).thenReturn(offer);

        var result = persistenceService.saveCredentialOffer(offer);

        assertEquals(offer, result);
        verify(credentialOfferRepository, times(1)).save(offer);
        verifyNoMoreInteractions(credentialOfferRepository);
    }

    /**
     * Happy path: finding an existing credential management by its id.
     */
    @Test
    void findCredentialManagementById_shouldReturnWhenFound() {
        var id = UUID.randomUUID();
        var mgmt = CredentialManagement.builder().id(id).build();
        when(credentialManagementRepository.findById(id)).thenReturn(Optional.of(mgmt));

        var result = persistenceService.findCredentialManagementById(id);

        assertEquals(mgmt, result);
    }

    /**
     * Happy path: finding an existing credential offer by its id using a lock ("for update").
     */
    @Test
    void findCredentialOfferByIdForUpdate_shouldReturnWhenFound() {
        var id = UUID.randomUUID();
        var offer = CredentialOffer.builder().id(id).build();
        when(credentialOfferRepository.findByIdForUpdate(id)).thenReturn(Optional.of(offer));

        var result = persistenceService.findCredentialOfferByIdForUpdate(id);

        assertEquals(offer, result);
    }

    /**
     * Happy path: finding the current/active credential offer for a given tenant id.
     */
    @Test
    void findCredentialOfferByMetadataTenantId_shouldReturnWhenFound() {
        var tenantId = UUID.randomUUID();
        var management = CredentialManagement.builder().id(UUID.randomUUID()).metadataTenantId(tenantId).build();
        var offer = CredentialOffer.builder().id(UUID.randomUUID()).credentialManagement(management).build();
        when(credentialOfferRepository.findLatestOffersByMetadataTenantId(Mockito.eq(tenantId), Mockito.any())).thenReturn(List.of(offer));

        var result = persistenceService.findCredentialOfferByMetadataTenantId(tenantId);

        assertEquals(offer, result);
    }

    /**
     * Verifies that fetching credential offer statuses delegates to the repository.
     */
    @Test
    void findCredentialOfferStatusesByOfferIds_shouldReturnRepositoryResult() {
        var offerIds = List.of(UUID.randomUUID(), UUID.randomUUID());
        var statusListId = UUID.randomUUID();

        var status1 = CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder().offerId(offerIds.get(0)).statusListId(statusListId).index(1).build())
                .build();
        var status2 = CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder().offerId(offerIds.get(1)).statusListId(statusListId).index(2).build())
                .build();

        Set<CredentialOfferStatus> expected = new HashSet<>(Set.of(status1, status2));
        when(credentialOfferStatusRepository.findByOfferIdIn(offerIds)).thenReturn(expected);

        var result = persistenceService.findCredentialOfferStatusesByOfferIds(offerIds);

        assertEquals(expected, result);
        verify(credentialOfferStatusRepository).findByOfferIdIn(offerIds);
        verifyNoMoreInteractions(credentialOfferStatusRepository);
    }

    /**
     * Happy path: returns the list of expired offers from the repository.
     */
    @Test
    void findExpiredOffers_shouldReturnList() {
        var expireStates = List.of(CredentialOfferStatusType.OFFERED);
        var expireTimeStamp = 123456L;
        var offers = List.of(
                CredentialOffer.builder().id(UUID.randomUUID()).build(),
                CredentialOffer.builder().id(UUID.randomUUID()).build()
        );

        when(credentialOfferRepository.findByCredentialStatusInAndOfferExpirationTimestampLessThan(
                expireStates, expireTimeStamp))
                .thenReturn(offers.stream());

        var result = persistenceService.findExpiredOffers(expireStates, expireTimeStamp);

        assertEquals(2, result.size());
        assertEquals(offers, result);
    }

    /**
     * Happy path: returns the count of expired offers from the repository.
     */
    @Test
    void countExpiredOffers_shouldReturnCount() {
        var expireStates = List.of(CredentialOfferStatusType.OFFERED);
        var expireTimeStamp = 123456L;

        when(credentialOfferRepository.countByCredentialStatusInAndOfferExpirationTimestampLessThan(
                expireStates, expireTimeStamp))
                .thenReturn(5L);

        var result = persistenceService.countExpiredOffers(expireStates, expireTimeStamp);

        assertEquals(5L, result);
    }

    /**
     * Happy path: status list entries should be created and stored for a single status list.
     *
     * <p>This test intentionally does not depend on deterministic randomness. It asserts that
     * exactly {@code issuanceBatchSize} entries are created and that each entry is associated with
     * the expected offer id and status list id.</p>
     */
    @Test
    void saveStatusListEntries_shouldSaveEntries() {
        var statusList = StatusList.builder()
                .id(UUID.randomUUID())
                .uri("https://example.com/status")
                .build();
        var offerId = UUID.randomUUID();

        var freeIndexes = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        var availableIndexes = AvailableStatusListIndexes.builder()
                .statusListUri(statusList.getUri())
                .freeIndexes(new ArrayList<>(freeIndexes))
                .build();

        when(availableStatusListIndexRepository.findById(statusList.getUri()))
                .thenReturn(Optional.of(availableIndexes));

        persistenceService.saveStatusListEntries(List.of(statusList), offerId, 3);

        var captor = org.mockito.ArgumentCaptor.forClass(Iterable.class);
        verify(credentialOfferStatusRepository, times(1)).saveAll(captor.capture());

        var savedIterable = captor.getValue();
        assertNotNull(savedIterable);

        var saved = new ArrayList<CredentialOfferStatus>();
        for (Object o : savedIterable) {
            saved.add((CredentialOfferStatus) o);
        }

        assertEquals(3, saved.size());
        for (var s : saved) {
            assertNotNull(s.getId());
            assertEquals(offerId, s.getId().getOfferId());
            assertEquals(statusList.getId(), s.getId().getStatusListId());
            assertTrue(freeIndexes.contains(s.getId().getIndex()));
        }
    }

    /**
     * Happy path: when multiple status lists are supplied, entries should be stored per status list.
     */
    @Test
    void saveStatusListEntries_shouldSaveEntriesForMultipleStatusLists() {
        var offerId = UUID.randomUUID();
        var issuanceBatchSize = 2;

        var statusList1 = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/status/1").build();
        var statusList2 = StatusList.builder().id(UUID.randomUUID()).uri("https://example.com/status/2").build();

        var freeIndexes1 = Arrays.asList(1, 2, 3, 4);
        var freeIndexes2 = Arrays.asList(10, 11, 12, 13);

        when(availableStatusListIndexRepository.findById(statusList1.getUri()))
                .thenReturn(Optional.of(AvailableStatusListIndexes.builder()
                        .statusListUri(statusList1.getUri())
                        .freeIndexes(new ArrayList<>(freeIndexes1))
                        .build()));

        when(availableStatusListIndexRepository.findById(statusList2.getUri()))
                .thenReturn(Optional.of(AvailableStatusListIndexes.builder()
                        .statusListUri(statusList2.getUri())
                        .freeIndexes(new ArrayList<>(freeIndexes2))
                        .build()));

        persistenceService.saveStatusListEntries(List.of(statusList1, statusList2), offerId, issuanceBatchSize);

        // one saveAll call per StatusList
        verify(credentialOfferStatusRepository, times(2)).saveAll(any());
    }

    /**
     * Exception path: if no indexes are available for the given status list URI, the method must fail.
     */
    @Test
    void saveStatusListEntries_shouldThrowWhenNoIndexesAvailable() {
        var statusList = StatusList.builder()
                .id(UUID.randomUUID())
                .uri("https://example.com/status")
                .build();
        var offerId = UUID.randomUUID();

        when(availableStatusListIndexRepository.findById(statusList.getUri()))
                .thenReturn(Optional.empty());

        var ex = assertThrows(BadRequestException.class,
                () -> persistenceService.saveStatusListEntries(List.of(statusList), offerId, 3));
        assertTrue(ex.getMessage().contains(statusList.getUri()));
    }

    /**
     * Exception path: if less than {@code issuanceBatchSize} free indexes exist, the method must fail.
     */
    @Test
    void saveStatusListEntries_shouldThrowWhenNotEnoughIndexesAvailable() {
        var statusList = StatusList.builder()
                .id(UUID.randomUUID())
                .uri("https://example.com/status")
                .build();
        var offerId = UUID.randomUUID();

        var freeIndexes = Arrays.asList(1, 2); // only two free indexes
        when(availableStatusListIndexRepository.findById(statusList.getUri()))
                .thenReturn(Optional.of(AvailableStatusListIndexes.builder()
                        .statusListUri(statusList.getUri())
                        .freeIndexes(freeIndexes)
                        .build()));

        var ex = assertThrows(BadRequestException.class,
                () -> persistenceService.saveStatusListEntries(List.of(statusList), offerId, 3));
        assertTrue(ex.getMessage().contains(statusList.getUri()));
    }

    /**
     * Ensures getRandomIndexes never reuses indexes and only returns unique values from the freeIndexes list.
     */
    @Test
    void getRandomIndexes_shouldReturnUniqueIndexes() {
        // Arrange
        var statusList = StatusList.builder()
                .id(UUID.randomUUID())
                .uri("https://example.com/status")
                .build();
        List<Integer> freeIndexes = Arrays.asList(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
        var availableIndexes = AvailableStatusListIndexes.builder()
                .statusListUri(statusList.getUri())
                .freeIndexes(new ArrayList<>(freeIndexes))
                .build();
        when(availableStatusListIndexRepository.findById(statusList.getUri()))
                .thenReturn(Optional.of(availableIndexes));

        int batchSize = 5;

        Set<Integer> result = persistenceService.getRandomIndexes(batchSize, statusList);

        // Assert
        assertEquals(batchSize, result.size(), "Should return exactly batchSize unique indexes");
        assertTrue(freeIndexes.containsAll(result), "All returned indexes must be from the original freeIndexes");
        // Ensure no duplicates (Set guarantees this, but we check for clarity)
        assertEquals(batchSize, result.stream().distinct().count(), "No duplicate indexes should be present");
    }
}
