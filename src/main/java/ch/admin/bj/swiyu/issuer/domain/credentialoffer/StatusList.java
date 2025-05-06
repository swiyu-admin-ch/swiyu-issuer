/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.AuditMetadata;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A representation of any form of status list which can be represented as
 * String
 * Non-exhaustive list of examples:
 * <ul>
 * <li><a href="https://www.w3.org/TR/vc-bitstring-status-list/">Bitstring
 * status list</a></li>
 * <li><a href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html">Token
 * Status List</a></li>
 * </ul>
 */
@Slf4j
@Entity
@Table(name = "status_list")
@NoArgsConstructor
@AllArgsConstructor
@Getter // do not apply generell setters on entities
@Setter
@Builder
@EntityListeners(AuditingEntityListener.class)
public class StatusList {
    @Embedded
    @Valid
    private final AuditMetadata auditMetadata = new AuditMetadata();

    @Id
    @Builder.Default
    private UUID id = UUID.randomUUID(); // Generate the ID manually

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
    @NotNull
    private Integer nextFreeIndex;
    /**
     * The maximum number of entries this status list is made for
     */
    @NotNull
    private Integer maxLength;

    public UUID getRegistryId() {
        /**
         * Currently we have a public interface which inputs only the whole URL for the
         * statuslist.
         * To not change that interface we extract the id from the url we receive.
         */

        // Define the regex pattern for a UUID
        String uuidPattern = ".*([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}).*";
        Pattern pattern = Pattern.compile(uuidPattern);
        Matcher matcher = pattern.matcher(this.uri);

        // Find and return the first UUID found in the URL
        if (matcher.find()) {
            return UUID.fromString(matcher.group(1));
        } else {
            log.warn(String.format("Extracting datastore entry from the status list uri %s using regex %s failed", uri,
                    uuidPattern));
            throw new IllegalArgumentException("No UUID found in the provided URL.");
        }
    }

    public void setStatusZipped(String statusZipped) {
        this.statusZipped = statusZipped;
    }

    public void incrementNextFreeIndex() {
        this.nextFreeIndex++;
    }
}
