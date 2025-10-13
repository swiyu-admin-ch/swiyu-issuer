package ch.admin.bj.swiyu.issuer.domain.openid;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface EncryptionKeyRepository extends JpaRepository<EncryptionKey, UUID> {
}
