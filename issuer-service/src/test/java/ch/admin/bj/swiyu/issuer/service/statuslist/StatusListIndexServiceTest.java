package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.AvailableStatusListIndexRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.AvailableStatusListIndexes;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link StatusListIndexService}.
 *
 * <p>All tests target {@link StatusListIndexService#getRandomIndexes} directly, since
 * {@link StatusListIndexService#claimRandomIndexes} requires an active transaction
 * ({@code Propagation.MANDATORY}) and is therefore covered by integration tests.</p>
 */
class StatusListIndexServiceTest {

    private AvailableStatusListIndexRepository availableStatusListIndexRepository;
    private StatusListRepository statusListRepository;
    private StatusListIndexService service;

    @BeforeEach
    void setUp() {
        availableStatusListIndexRepository = mock(AvailableStatusListIndexRepository.class);
        statusListRepository = mock(StatusListRepository.class);
        service = new StatusListIndexService(availableStatusListIndexRepository, statusListRepository);
    }

    // ---------------------------------------------------------------------------
    // getRandomIndexes – happy path
    // ---------------------------------------------------------------------------

    /**
     * Verifies that the returned set contains exactly {@code batchSize} elements
     * when enough free indexes are available.
     */
    @Test
    void getRandomIndexes_whenEnoughIndexesAvailable_returnsRequestedCount() {
        var statusList = buildStatusList();
        stubFreeIndexes(statusList, List.of(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));

        Set<Integer> result = service.getRandomIndexes(3, statusList);

        assertThat(result).hasSize(3);
    }

    /**
     * Verifies that all returned indexes are contained in the available pool.
     */
    @Test
    void getRandomIndexes_whenEnoughIndexesAvailable_returnsSubsetOfFreeIndexes() {
        var statusList = buildStatusList();
        var freeIndexes = List.of(10, 20, 30, 40, 50);
        stubFreeIndexes(statusList, freeIndexes);

        Set<Integer> result = service.getRandomIndexes(3, statusList);

        assertThat(result).isSubsetOf(freeIndexes);
    }

    /**
     * Verifies that the returned set contains no duplicate indexes.
     */
    @Test
    void getRandomIndexes_whenEnoughIndexesAvailable_returnsNoDuplicates() {
        var statusList = buildStatusList();
        stubFreeIndexes(statusList, List.of(1, 2, 3, 4, 5));

        Set<Integer> result = service.getRandomIndexes(5, statusList);

        // A Set cannot contain duplicates; asserting the size proves uniqueness.
        assertThat(result).hasSize(5);
    }

    /**
     * Verifies that claiming exactly all available indexes succeeds.
     */
    @Test
    void getRandomIndexes_whenBatchSizeEqualsAvailableCount_returnsAllIndexes() {
        var statusList = buildStatusList();
        var freeIndexes = List.of(7, 8, 9);
        stubFreeIndexes(statusList, freeIndexes);

        Set<Integer> result = service.getRandomIndexes(3, statusList);

        assertThat(result).containsExactlyInAnyOrderElementsOf(freeIndexes);
    }

    // ---------------------------------------------------------------------------
    // getRandomIndexes – error cases
    // ---------------------------------------------------------------------------

    /**
     * Verifies that a {@link BadRequestException} is thrown when no entry exists
     * in the available-index view for the given status list URI.
     */
    @Test
    void getRandomIndexes_whenNoViewEntryExists_throwsBadRequestException() {
        var statusList = buildStatusList();
        when(availableStatusListIndexRepository.findById(statusList.getUri()))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getRandomIndexes(1, statusList))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining(statusList.getUri());
    }

    /**
     * Verifies that a {@link BadRequestException} is thrown when the available pool
     * is smaller than the requested batch size.
     */
    @Test
    void getRandomIndexes_whenTooFewIndexesAvailable_throwsBadRequestException() {
        var statusList = buildStatusList();
        stubFreeIndexes(statusList, List.of(0, 1)); // only 2 available

        assertThatThrownBy(() -> service.getRandomIndexes(3, statusList))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining(statusList.getUri());
    }

    /**
     * Verifies that a {@link BadRequestException} is thrown when the available pool
     * is completely empty (view entry exists but list is empty).
     */
    @Test
    void getRandomIndexes_whenFreeIndexListIsEmpty_throwsBadRequestException() {
        var statusList = buildStatusList();
        stubFreeIndexes(statusList, List.of());

        assertThatThrownBy(() -> service.getRandomIndexes(1, statusList))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining(statusList.getUri());
    }

    // ---------------------------------------------------------------------------
    // claimRandomIndexes – lock verification
    // ---------------------------------------------------------------------------

    /**
     * Verifies that {@link StatusListIndexService#claimRandomIndexes} acquires a
     * pessimistic write lock on the {@link StatusList} row before reading the
     * available-index view.
     *
     * <p>The {@code @Transactional(MANDATORY)} constraint is not enforced in a plain
     * unit test; only the lock call itself is verified here.</p>
     */
    @Test
    void claimRandomIndexes_alwaysLocksStatusListBeforeReadingView() {
        var statusList = buildStatusList();
        stubFreeIndexes(statusList, List.of(1, 2, 3, 4, 5));
        when(statusListRepository.findByIdLocked(statusList.getId()))
                .thenReturn(Optional.of(statusList));

        service.claimRandomIndexes(statusList, 2);

        verify(statusListRepository).findByIdLocked(statusList.getId());
    }

    /**
     * Verifies that {@link StatusListIndexService#claimRandomIndexes} returns the
     * correct number of indexes after acquiring the lock.
     */
    @Test
    void claimRandomIndexes_whenLockAcquired_returnsRequestedIndexes() {
        var statusList = buildStatusList();
        stubFreeIndexes(statusList, List.of(10, 20, 30));
        when(statusListRepository.findByIdLocked(statusList.getId()))
                .thenReturn(Optional.of(statusList));

        Set<Integer> result = service.claimRandomIndexes(statusList, 2);

        assertThat(result).hasSize(2).isSubsetOf(10, 20, 30);
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private StatusList buildStatusList() {
        return StatusList.builder()
                .id(UUID.randomUUID())
                .uri("https://example.com/statuslist/test-" + UUID.randomUUID())
                .statusZipped("dummyZipped")
                .maxLength(255)
                .build();
    }

    /**
     * Stubs the available-index view for the given status list.
     * A mutable copy of the index list is used because {@link StatusListIndexService#getRandomIndexes}
     * calls {@link List#remove} on the returned list during sampling.
     */
    private void stubFreeIndexes(StatusList statusList, List<Integer> indexes) {
        var mutableIndexes = new ArrayList<>(indexes);
        var view = mock(AvailableStatusListIndexes.class);
        when(view.getFreeIndexes()).thenReturn(mutableIndexes);
        when(availableStatusListIndexRepository.findById(statusList.getUri()))
                .thenReturn(Optional.of(view));
    }
}

