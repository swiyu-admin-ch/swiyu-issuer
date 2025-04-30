/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CredentialOfferRepository extends JpaRepository<CredentialOffer, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByPreAuthorizedCode(UUID uuid);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByAccessToken(UUID accessToken);
}