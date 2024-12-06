package ch.admin.bit.eid.issuer_management.domain.ecosystem;

import ch.admin.bit.eid.issuer_management.enums.EcosystemApiEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenSetRepository extends JpaRepository<TokenSetEntity, EcosystemApiEnum> {

}
