package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface IssuerSecretRepository extends JpaRepository<IssuerSecret, UUID>{
    
}
