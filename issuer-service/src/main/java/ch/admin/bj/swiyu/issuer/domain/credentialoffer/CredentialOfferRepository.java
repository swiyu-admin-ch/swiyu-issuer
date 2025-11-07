/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

@Repository
public interface CredentialOfferRepository extends JpaRepository<CredentialOffer, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByPreAuthorizedCode(UUID uuid);

    @Deprecated(since = "DB 1_4_0")
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByAccessToken(UUID accessToken);

    @Deprecated(since = "DB 1_4_0")
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByRefreshToken(UUID refreshToken);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<CredentialOffer> findByCredentialManagementId(UUID credentialManagementId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByTransactionId(UUID transactionId);

    Optional<CredentialOffer> findByMetadataTenantId(UUID tenantId);

    @Query("SELECT c FROM CredentialOffer c WHERE :uuid = c.id")
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByIdForUpdate(UUID uuid);

    long countByCredentialStatusInAndOfferExpirationTimestampLessThan(Collection<CredentialStatusType> credentialStatuses, long offerExpirationTimestampIsLessThan);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Stream<CredentialOffer> findByCredentialStatusInAndOfferExpirationTimestampLessThan(Collection<CredentialStatusType> credentialStatuses, long offerExpirationTimestampIsLessThan);
}