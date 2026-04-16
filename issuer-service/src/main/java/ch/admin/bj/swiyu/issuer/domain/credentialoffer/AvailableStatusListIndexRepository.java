package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AvailableStatusListIndexRepository extends JpaRepository<AvailableStatusListIndexes, String> {
}
