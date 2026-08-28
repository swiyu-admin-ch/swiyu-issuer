package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.LockModeType;
import jakarta.persistence.QueryHint;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CredentialManagementRepository extends JpaRepository<CredentialManagement, UUID> {

    /**
     * Bounds how long a caller waits to acquire the pessimistic write lock on the
     * CredentialManagement row, in milliseconds. Renewal holds this lock for the
     * duration of its synchronous business-issuer HTTP call, which currently has no
     * enforced timeout of its own (a separate, pre-existing issue). This hint puts an
     * upper bound on that specific wait regardless, so a concurrent status change fails
     * fast with a clear error instead of hanging on the caller side indefinitely.
     */
    String LOCK_TIMEOUT_MILLIS = "45000";

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout", value = LOCK_TIMEOUT_MILLIS))
    Optional<CredentialManagement> findByAccessToken(UUID accessToken);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout", value = LOCK_TIMEOUT_MILLIS))
    Optional<CredentialManagement> findByRefreshToken(UUID refreshToken);

    /**
     * Not thread safe
     */
    Optional<CredentialManagement> findByMetadataTenantId(UUID tenantId);

    /**
     * Loads a CredentialManagement with a pessimistic write lock, so that it is
     * serialized against concurrent renewal (which locks the same row via
     * {@link #findByAccessToken} / {@link #findByRefreshToken}) for the duration
     * of the surrounding transaction.
     */
    @Query("SELECT m FROM CredentialManagement m WHERE :id = m.id")
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout", value = LOCK_TIMEOUT_MILLIS))
    Optional<CredentialManagement> findByIdForUpdate(UUID id);
}