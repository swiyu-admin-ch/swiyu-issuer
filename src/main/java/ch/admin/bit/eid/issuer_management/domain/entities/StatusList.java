/*
 * SPDX-FileCopyrightText: 2024 Swiss Confederation
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bit.eid.issuer_management.domain.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "status_list")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StatusList {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String type;
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> config;
    private String uri;
    private String statusZipped;
    private Integer lastUsedIndex;
    private Integer maxLength;

    @OneToMany(mappedBy = "statusList")
    private Set<CredentialOfferStatus> offerStatusSet;
}
