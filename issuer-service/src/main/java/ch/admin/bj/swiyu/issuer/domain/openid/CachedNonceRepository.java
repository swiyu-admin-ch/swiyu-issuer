package ch.admin.bj.swiyu.issuer.domain.openid;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.UUID;

public interface CachedNonceRepository extends JpaRepository<CachedNonce, UUID> {

    @Modifying
    @Query("delete from CachedNonce c where c.timestamp < :deleteTime")
    void deleteAllOlderThan(@Param("deleteTime") Instant deleteTime);

}
