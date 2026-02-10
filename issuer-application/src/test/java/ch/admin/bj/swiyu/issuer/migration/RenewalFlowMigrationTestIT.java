/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.migration;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.migration.domain.CredentialOfferData;
import ch.admin.bj.swiyu.issuer.migration.domain.CredentialOfferTestFactory;
import lombok.extern.slf4j.Slf4j;
import org.flywaydb.core.Flyway;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.postgresql.util.PGobject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@TestPropertySource(properties = {
        "spring.jpa.hibernate.ddl-auto=none",
        "spring.jpa.properties.hibernate.default_schema=test_migration"
})
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RenewalFlowMigrationTestIT {

    private static final String SCHEMA = "test_migration";

    private static final List<String> MIGRATION_LOCATIONS = List.of(
            "classpath:db/migration/common",
            "classpath:db/migration/postgres"
    );

    private static final String PRE_MIGRATION_TARGET = "1.3.0";
    private static final String MIGRATION_TARGET = "1.4.1";
    final Map<String, CredentialOfferStatusType> offerStatusMapping = Map.of(
            "OFFERED", CredentialOfferStatusType.OFFERED,
            "CANCELLED", CredentialOfferStatusType.CANCELLED,
            "IN_PROGRESS", CredentialOfferStatusType.IN_PROGRESS,
            "DEFERRED", CredentialOfferStatusType.DEFERRED,
            "READY", CredentialOfferStatusType.READY,
            "ISSUED", CredentialOfferStatusType.ISSUED,
            "SUSPENDED", CredentialOfferStatusType.ISSUED,
            "REVOKED", CredentialOfferStatusType.ISSUED,
            "EXPIRED", CredentialOfferStatusType.EXPIRED
    );
    final Map<String, CredentialStatusManagementType> managementStatusMapping = Map.of(
            "OFFERED", CredentialStatusManagementType.INIT,
            "CANCELLED", CredentialStatusManagementType.INIT,
            "IN_PROGRESS", CredentialStatusManagementType.INIT,
            "DEFERRED", CredentialStatusManagementType.INIT,
            "READY", CredentialStatusManagementType.INIT,
            "ISSUED", CredentialStatusManagementType.ISSUED,
            "SUSPENDED", CredentialStatusManagementType.SUSPENDED,
            "REVOKED", CredentialStatusManagementType.REVOKED,
            "EXPIRED", CredentialStatusManagementType.INIT
    );
    final List<CredentialOfferData> DATASET_1_3 = List.of(
            CredentialOfferTestFactory.offered(),
            CredentialOfferTestFactory.cancelled(),
            CredentialOfferTestFactory.inProgress(),
            CredentialOfferTestFactory.deferred(),
            CredentialOfferTestFactory.ready(),
            CredentialOfferTestFactory.issued(),
            CredentialOfferTestFactory.suspended(),
            CredentialOfferTestFactory.revoked(),
            CredentialOfferTestFactory.expired()
    );
    @Autowired
    DataSource dataSource;
    @Autowired
    JdbcTemplate jdbcTemplate;
    @Autowired
    CredentialOfferRepository credentialOfferRepository;
    @Autowired
    CredentialManagementRepository credentialManagementRepository;
    Map<UUID, CredentialOfferData> offers = new HashMap<>();
    private List<CredentialOfferData> renewedCredentialOffers;

    private static @NonNull PGobject prepareCredentialSupportedId(String value) throws SQLException {
        var supportedId = new PGobject();
        supportedId.setType("jsonb");
        supportedId.setValue(value);
        return supportedId;
    }

    private static @Nullable Object prepareDpop(CredentialOfferData data) throws SQLException {
        Object dpopJsonb = null;
        if (data.getDpopKey() != null) {
            var dpop = prepareCredentialSupportedId(data.getDpopKey());
            dpopJsonb = dpop;
        }
        return dpopJsonb;
    }

    @BeforeAll
    void migrateDatabase() {
        jdbcTemplate.execute("CREATE SCHEMA IF NOT EXISTS " + SCHEMA);
        jdbcTemplate.execute("SET search_path TO " + SCHEMA);

        final Flyway preFlyway = Flyway.configure()
                .dataSource(dataSource)
                .schemas(SCHEMA)
                .defaultSchema(SCHEMA)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .target(PRE_MIGRATION_TARGET)
                .cleanDisabled(false)
                .load();

        log.info("Reset migration schema");
        preFlyway.clean();

        log.info("Migrating schema to {}", PRE_MIGRATION_TARGET);
        preFlyway.migrate();

        log.info("Loading test data");
        DATASET_1_3.forEach(this::insert_1_3);

        offers = DATASET_1_3.stream()
                .collect(Collectors.toMap(CredentialOfferData::getId, it -> it));

        final Flyway postFlyway_1_4 = Flyway.configure()
                .dataSource(dataSource)
                .schemas(SCHEMA)
                .defaultSchema(SCHEMA)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .target(MIGRATION_TARGET)
                .cleanDisabled(false)
                .load();

        log.info("Migrating schema to {}", MIGRATION_TARGET);
        postFlyway_1_4.migrate();

        // Add additional entries to existing management entries
        var issuedManagementEntities = offers.entrySet().stream()
                .filter(e -> "ISSUED".equals(e.getValue().getOfferStatus()))
                .map(Map.Entry::getKey)
                .toList();
        renewedCredentialOffers = issuedManagementEntities.stream().map(managementId -> {
            var renewalOffer = CredentialOfferTestFactory.offered();
            renewalOffer.setCredentialManagementId(managementId);
            return renewalOffer;
        }).toList();
        renewedCredentialOffers.forEach(this::insert_1_4);


        final Flyway postFlyway_1_5 = Flyway.configure()
                .dataSource(dataSource)
                .schemas(SCHEMA)
                .defaultSchema(SCHEMA)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .target("1.5.0")
                .cleanDisabled(false)
                .load();

        postFlyway_1_5.migrate();

    }

    @AfterAll
    void cleanupMigrationSchema() {
        log.info("Dropping migration schema");
        jdbcTemplate.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
    }

    /**
     * 1_4_0 Migration
     */
    @Test
    void should_preserve_offer_and_management_count_and_link_by_id() {
        final List<CredentialOffer> allOffers = credentialOfferRepository.findAll();
        final List<CredentialManagement> allManagements = credentialManagementRepository.findAll();

        assertThat(allOffers).hasSize(DATASET_1_3.size() + renewedCredentialOffers.size());
        assertThat(allManagements).hasSameSizeAs(DATASET_1_3);

        for (CredentialOffer offer : allOffers) {
            if (renewedCredentialOffers.stream().anyMatch(o -> o.getId().equals(offer.getId()))) {
                // The offer found is a renewal offer from 1_5 migration
                continue;
            }
            assertThat(offer.getCredentialManagement()).isNotNull();
            assertThat(offer.getCredentialManagement().getId()).isEqualTo(offer.getId());
        }
    }

    /**
     * 1_4_0 Migration
     */
    @Test
    void should_migrate_offer_status_correctly() {
        for (UUID id : offers.keySet()) {
            final CredentialOfferData before = offers.get(id);
            final CredentialOffer offer = credentialOfferRepository.findById(id).orElseThrow();

            assertThat(offer.getCredentialStatus())
                    .isEqualTo(offerStatusMapping.get(before.getOfferStatus()));
        }
    }

    /**
     * 1_4_0 Migration
     */
    @Test
    void should_migrate_management_statuses_correctly() {
        for (UUID id : offers.keySet()) {
            final CredentialOfferData before = offers.get(id);
            final CredentialManagement management =
                    credentialManagementRepository.findById(id).orElseThrow();

            assertThat(management.getCredentialManagementStatus())
                    .isEqualTo(managementStatusMapping.get(before.getOfferStatus()));
        }
    }

    /**
     * 1_4_0 Migration
     */
    @Test
    void should_copy_and_remove_token_related_fields_correctly() {
        for (var entry : offers.entrySet()) {
            final UUID id = entry.getKey();
            final CredentialOfferData before = entry.getValue();

            final CredentialManagement management =
                    credentialManagementRepository.findById(id).orElseThrow();

            assertThat(management.getAccessToken()).isEqualTo(before.getAccessToken());
            assertThat(management.getRefreshToken()).isEqualTo(before.getRefreshToken());
            assertThat(management.getAccessTokenExpirationTimestamp())
                    .isEqualTo(before.getTokenExpirationTimestamp());

            if (before.getDpopKey() == null) {
                assertThat(management.getDpopKey()).isNull();
            } else {
                assertThat(management.getDpopKey())
                        .containsKeys("x", "y", "crv", "kty", "use", "kid");
            }


        }
    }

    /**
     * 1_4_0 Migration
     */
    @Test
    void credential_offer_should_not_contain_token_related_columns_anymore() {
        final List<String> columnNames =
                jdbcTemplate.queryForList(
                        """
                                SELECT column_name
                                FROM information_schema.columns
                                WHERE table_schema = ?
                                  AND table_name = 'credential_offer'
                                """,
                        String.class,
                        SCHEMA
                );

        assertThat(columnNames).doesNotContain(
                "access_token",
                "refresh_token",
                "dpop_key",
                "token_expiration_timestamp"
        );
    }

    /**
     * 1_5_0 Migration
     */
    @Test
    void metadataTenantId_migrated_to_management() {
        var renewedManagement = credentialManagementRepository.findAll()
                .stream()
                .filter(cm -> cm.getCredentialOffers().size() > 1)
                .toList();
        assertThat(renewedManagement).hasSameSizeAs(renewedCredentialOffers);
        for (var rmgmt : renewedManagement) {
            var initialOffer = credentialOfferRepository.findById(rmgmt.getId());
            assertThat(initialOffer.isPresent())
                    .as("The initial offer should have the same ID as the management entity after migration")
                    .isTrue();
            var offer = credentialOfferRepository.findLatestOffersByMetadataTenantId(rmgmt.getMetadataTenantId(), PageRequest.of(0, 1));
            assertThat(offer)
                    .as("Should find the secondary offer that has been migrated")
                    .hasSize(1);
            assertThat(offer.getFirst())
                    .as("The latest offer found should be not the initial offer")
                    .isNotEqualTo(initialOffer.get().getId());

        }
    }

    void insert_1_3(CredentialOfferData data) {
        try {
            Object dpopJsonb = prepareDpop(data);

            var supportedId = prepareCredentialSupportedId("[\"unbound_example_sd_jwt\"]");

            jdbcTemplate.update("""
                            INSERT INTO credential_offer (
                                id,
                                nonce,
                                credential_status,
                                metadata_credential_supported_id,
                                access_token,
                                refresh_token,
                                dpop_key,
                                token_expiration_timestamp,
                                metadata_tenant_id
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    data.getId(),
                    UUID.randomUUID(),
                    data.getOfferStatus(),
                    supportedId,
                    data.getAccessToken(),
                    data.getRefreshToken(),
                    dpopJsonb,
                    data.getTokenExpirationTimestamp(),
                    data.getMetadataTenantId()
            );

        } catch (Exception e) {
            throw new IllegalStateException("Invalid SQL insert test data", e);
        }
    }

    /**
     * Insert data with a link to the management entity
     */
    void insert_1_4(CredentialOfferData data) {
        try {
            var supportedId = prepareCredentialSupportedId("[\"unbound_example_sd_jwt\"]");

            jdbcTemplate.update("""
                            INSERT INTO credential_offer (
                                id,
                                nonce,
                                credential_status,
                                metadata_credential_supported_id,
                                credential_management_id
                            )
                            VALUES (?, ?, ?, ?, ?)
                            """,
                    data.getId(),
                    UUID.randomUUID(),
                    data.getOfferStatus(),
                    supportedId,
                    data.getCredentialManagementId()
            );

        } catch (Exception e) {
            throw new IllegalStateException("Invalid SQL insert test data", e);
        }
    }
}
