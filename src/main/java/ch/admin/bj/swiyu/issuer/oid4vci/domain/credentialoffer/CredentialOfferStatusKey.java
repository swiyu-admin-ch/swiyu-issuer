/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

@Embeddable
@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor
public class CredentialOfferStatusKey implements Serializable {
    @Column(name = "credential_offer_id")
    private UUID offerId;

    @Column(name = "status_list_id")
    private UUID statusListId;
}
