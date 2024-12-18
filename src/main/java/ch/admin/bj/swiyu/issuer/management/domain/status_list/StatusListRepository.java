package ch.admin.bj.swiyu.issuer.management.domain.status_list;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface StatusListRepository extends JpaRepository<StatusListEntity, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<StatusListEntity> findByUriIn(List<String> uris);

    boolean existsByUri(String uri);
}
