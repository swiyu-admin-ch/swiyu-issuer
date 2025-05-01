/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

@Repository
public interface CredentialOfferRepository extends JpaRepository<CredentialOffer, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByPreAuthorizedCode(UUID uuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByAccessToken(UUID accessToken);

    @Query("SELECT c FROM CredentialOffer c WHERE :uuid = c.id")
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByIdForUpdate(UUID uuid);

    long countByCredentialStatusInAndOfferExpirationTimestampLessThan(Collection<CredentialStatusType> credentialStatuses, long offerExpirationTimestampIsLessThan);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Stream<CredentialOffer> findByCredentialStatusInAndOfferExpirationTimestampLessThan(Collection<CredentialStatusType> credentialStatuses, long offerExpirationTimestampIsLessThan);
}
