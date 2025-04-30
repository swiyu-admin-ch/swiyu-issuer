/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.oid4vci.domain.AuditMetadata;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "status_list")
@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@EntityListeners(AuditingEntityListener.class)
public class StatusList {

    @Embedded
    @Valid
    private final AuditMetadata auditMetadata = new AuditMetadata();

    @Id
    private UUID id;

    @Enumerated(EnumType.STRING)
    private StatusListType type;
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> config;
    private String uri;
    private String statusZipped;
    private Integer nextFreeIndex;
    private Integer maxLength;

    @OneToMany(mappedBy = "statusList")
    private Set<CredentialOfferStatus> offerStatusSet;

    // only needed for tests
    public void incrementIndex() {
        this.nextFreeIndex++;
    }
}
