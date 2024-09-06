package ch.admin.bit.eid.issuer_management.domain;

import ch.admin.bit.eid.issuer_management.domain.entities.StatusListEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface TokenStatusListRepository extends JpaRepository<StatusListEntity, UUID> {
}
