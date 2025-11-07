package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface CredentialManagementRepository extends JpaRepository<CredentialManagement, UUID> {

    @Query("SELECT c FROM CredentialManagement c WHERE :uuid = c.id")
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialManagement> findByIdForUpdate(UUID uuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialManagement> findByAccessToken(UUID accessToken);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialManagement> findByRefreshToken(UUID refreshToken);

}
