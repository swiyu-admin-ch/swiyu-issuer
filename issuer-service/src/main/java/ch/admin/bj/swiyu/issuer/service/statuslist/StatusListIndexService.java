package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.AvailableStatusListIndexRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Service responsible for claiming available status list indexes in a concurrency-safe manner.
 *
 * <p>Status list indexes are read from an {@code @Immutable} database view
 * ({@code available_status_list_indexes}). Because immutable views cannot be locked directly,
 * this service acquires a pessimistic write lock on the parent {@link StatusList} row first.
 * This serializes concurrent requests targeting the same status list and prevents duplicate
 * index assignments across threads or pods.</p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StatusListIndexService {

    private final AvailableStatusListIndexRepository availableStatusListIndexRepository;
    private final StatusListRepository statusListRepository;


    /**
     * Claims a set of random, unused status list indexes for a single issuance batch.
     *
     * <p>A pessimistic write lock is acquired on the {@link StatusList} row before the
     * available-index view is consulted. This guarantees that no two concurrent transactions
     * can read the same set of free indexes and therefore prevents duplicate index assignments.</p>
     *
     * <p>Must be called within an active transaction so that the lock is held until all
     * {@link ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus} entries
     * have been persisted. This method enforces that contract by requiring an existing
     * transaction ({@link Propagation#MANDATORY}); it will throw
     * {@link org.springframework.transaction.IllegalTransactionStateException} if called
     * without one.</p>
     *
     * @param statusList the status list from which indexes should be claimed
     * @param batchSize  the number of indexes to claim
     * @return an ordered set of claimed indexes with exactly {@code batchSize} elements
     * @throws BadRequestException if fewer than {@code batchSize} indexes are available
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public Set<Integer> claimRandomIndexes(StatusList statusList, int batchSize) {
        // Acquire a pessimistic write lock on the StatusList row before querying the
        // available-index view. The lock is held for the duration of the transaction,
        // serializing concurrent requests and preventing duplicate index assignments.
        statusListRepository.findByIdLocked(statusList.getId());

        return getRandomIndexes(batchSize, statusList);
    }

    /**
     * Reads the available indexes from the immutable view and draws a random sample.
     *
     * @param issuanceBatchSize the number of indexes needed
     * @param statusList        the status list whose free indexes should be sampled
     * @return a set of randomly selected available indexes
     * @throws BadRequestException if no indexes remain or fewer than {@code issuanceBatchSize}
     *                             indexes are available in the given status list
     */
    Set<Integer> getRandomIndexes(int issuanceBatchSize, StatusList statusList) {
        var freeIndexes = availableStatusListIndexRepository.findById(statusList.getUri())
                .orElseThrow(() -> new BadRequestException(
                        "No status indexes remain in status list %s to create credential offer"
                                .formatted(statusList.getUri())))
                .getFreeIndexes();

        if (freeIndexes.size() < issuanceBatchSize) {
            throw new BadRequestException(
                    "Too few status indexes remain in status list %s to create credential offer"
                            .formatted(statusList.getUri()));
        }

        // Draw a random sample without repetition from the pool of free indexes.
        Set<Integer> sampledNumbers = new LinkedHashSet<>();
        while (sampledNumbers.size() < issuanceBatchSize) {
            sampledNumbers.add(freeIndexes.remove(ThreadLocalRandom.current().nextInt(freeIndexes.size())));
        }
        return sampledNumbers;
    }

}
