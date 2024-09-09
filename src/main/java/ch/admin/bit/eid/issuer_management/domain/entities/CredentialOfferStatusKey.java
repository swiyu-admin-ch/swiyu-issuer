/*
 * SPDX-FileCopyrightText: 2024 Swiss Confederation
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bit.eid.issuer_management.domain.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Data;

import java.io.Serializable;
import java.util.UUID;

@Embeddable
@Data
public class CredentialOfferStatusKey implements Serializable {
    @Column(name = "credential_offer_id")
    private UUID offerId;

    @Column(name = "status_list_id")
    private UUID statusListId;
}
