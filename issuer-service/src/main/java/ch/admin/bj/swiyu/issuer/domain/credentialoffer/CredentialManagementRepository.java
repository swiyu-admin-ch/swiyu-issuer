package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CredentialManagementRepository extends JpaRepository<CredentialManagement, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialManagement> findByAccessToken(UUID accessToken);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
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
    Optional<CredentialManagement> findByIdForUpdate(UUID id);
}