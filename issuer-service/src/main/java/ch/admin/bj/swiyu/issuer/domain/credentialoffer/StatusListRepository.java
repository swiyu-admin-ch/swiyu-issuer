package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface StatusListRepository extends JpaRepository<StatusList, UUID> {
    @Query("SELECT c FROM StatusList c WHERE :uuid = c.id")
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<StatusList> findByIdForUpdate(UUID uuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<StatusList> findByUriIn(List<String> uris);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT s FROM StatusList s WHERE s.id IN :ids")
    List<StatusList> findAllByIdInForUpdate(List<UUID> ids);
}
