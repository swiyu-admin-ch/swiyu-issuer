/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Set;
import java.util.UUID;

@Repository
public interface CredentialOfferStatusRepository
        extends JpaRepository<CredentialOfferStatus, CredentialOfferStatusKey> {

    @Query("SELECT c FROM CredentialOfferStatus c WHERE :offerStatusId = c.id.offerId")
    Set<CredentialOfferStatus> findByOfferStatusId(UUID offerStatusId);
}
