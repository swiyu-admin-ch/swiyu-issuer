/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

@Embeddable
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialOfferStatusKey implements Serializable {
    @Column(name = "credential_offer_id")
    private UUID offerId;

    @Column(name = "status_list_id")
    private UUID statusListId;

    /**
     * The index the credential is assigned on the status list.
     * The corresponding status has to be calculated depending on the type of status
     * list using this index.
     */
    @Column(name = "index")
    private Integer index;
}
