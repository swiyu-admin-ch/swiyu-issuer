/*
 * SPDX-FileCopyrightText: 2024 Swiss Confederation
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bit.eid.issuer_management.domain.entities;

import ch.admin.bit.eid.issuer_management.models.statuslist.StatusListType;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * A representation of any form of status list which can be represented as String
 * Non-exhaustive list of examples:
 * <ul>
 * <li><a href="https://www.w3.org/TR/vc-bitstring-status-list/">Bitstring status list</a></li>
 * <li><a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html">Token Status List</a></li>
 * </ul>
 */
@Entity
@Table(name = "status_list")
@NoArgsConstructor
@AllArgsConstructor
@Getter // do not apply generell setters on entities
@Builder
public class StatusList {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @NotNull
    private StatusListType type;
    /**
     * The config of the status list, the exact content of which depend on the type
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> config;
    /**
     * The public read uri on any status registry
     */
    @NotNull
    private String uri;
    /**
     * The status data in compressed form
     */
    @NotNull
    private String statusZipped;
    /**
     * indicator what index is to be next used for creation of a new VC.
     */
    // TODO EID-1822 naming does not match the description, we actually store the nextFreeIndex
    @NotNull
    private Integer lastUsedIndex;
    /**
     * The maximum number of entries this status list is made for
     */
    @NotNull
    private Integer maxLength;

    @OneToMany(mappedBy = "statusList")
    private Set<CredentialOfferStatus> offerStatusSet;

    public void setStatusZipped(String statusZipped) {
        this.statusZipped = statusZipped;
    }

    public void incrementNextFreeIndex() {
        // TODO EID-1822 lastUsedIndex should be renamed to nextFreeIndex
        this.lastUsedIndex++;
    }
}
