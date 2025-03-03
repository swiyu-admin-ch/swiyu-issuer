/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Linking an Index on a Status List to a Verifiable Credential.
 * Using this the state of the credential can be changed
 */
@Entity
@Table(name = "credential_offer_status")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialOfferStatus {

    @EmbeddedId
    private CredentialOfferStatusKey id;

    @ManyToOne
    @MapsId("offerId")
    @JoinColumn(name = "credential_offer_id", referencedColumnName = "id")
    private CredentialOffer offer;

    @ManyToOne(fetch = FetchType.EAGER)
    @MapsId("statusListId")
    @JoinColumn(name = "status_list_id", referencedColumnName = "id")
    private StatusList statusList;

    /**
     * The index the credential is assigned on the status list.
     * The corresponding status has to be calculated depending on the type of status
     * list using this index.
     */
    @NotNull
    private Integer index;

}
