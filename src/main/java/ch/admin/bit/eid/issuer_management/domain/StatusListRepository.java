package ch.admin.bit.eid.issuer_management.domain;

import ch.admin.bit.eid.issuer_management.domain.entities.StatusList;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface StatusListRepository extends JpaRepository<StatusList, UUID> {
    List<StatusList> findByUriIn(List<String> uris);

    boolean existsByUri(String uri);
}
