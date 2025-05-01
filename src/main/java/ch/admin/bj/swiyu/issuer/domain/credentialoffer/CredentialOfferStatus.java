/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.AuditMetadata;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

/**
 * Linking an Index on a Status List to a Verifiable Credential.
 * Using this the state of the credential can be changed
 */
@Entity
@Table(name = "credential_offer_status")
@Getter
@Setter // TODO: do not apply setters on entities
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor // test data
@EntityListeners(AuditingEntityListener.class)
@Builder
public class CredentialOfferStatus {

    @Embedded
    @Valid
    private final AuditMetadata auditMetadata = new AuditMetadata();

    @EmbeddedId
    private CredentialOfferStatusKey id;

    @ManyToOne
    @MapsId("offerId")
    @JoinColumn(name = "credential_offer_id", referencedColumnName = "id")
    private CredentialOffer offer;

    // We explicitly want to break the hibernate connection to status list, that's why it is not mentioned here

    // TODO gapa: We should not use this here?
    @ManyToOne
    @MapsId("statusListId")
    @JoinColumn(name = "status_list_id", referencedColumnName = "id", updatable = false)
    // We have no reason to propagate the update, as there *should* be no use case for this
    private StatusList statusList;

    /**
     * The index the credential is assigned on the status list.
     * The corresponding status has to be calculated depending on the type of status
     * list using this index.
     */
    @NotNull
    private Integer index;

}
