package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
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
}