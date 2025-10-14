/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.AuditMetadata;
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
@Setter
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

}
