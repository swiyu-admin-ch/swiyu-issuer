package ch.admin.bit.swiyu.issuer.management.domain.ecosystem;

import ch.admin.bit.swiyu.issuer.management.enums.EcosystemApiEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenSetRepository extends JpaRepository<TokenSetEntity, EcosystemApiEnum> {

}
