package ch.admin.bj.swiyu.issuer.migration;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.migration.domain.CredentialOfferData;
import ch.admin.bj.swiyu.issuer.migration.domain.CredentialOfferTestFactory;
import lombok.extern.slf4j.Slf4j;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.postgresql.util.PGobject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import javax.sql.DataSource;
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
    private static final String MIGRATION_TARGET = "1.4.0";

    @Autowired
    DataSource dataSource;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    CredentialOfferRepository credentialOfferRepository;

    @Autowired
    CredentialManagementRepository credentialManagementRepository;

    Map<UUID, CredentialOfferData> offers = new HashMap<>();

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

    final List<CredentialOfferData> DATASET = List.of(
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
        DATASET.forEach(this::insert);

        offers = DATASET.stream()
                .collect(Collectors.toMap(CredentialOfferData::id, it -> it));

        final Flyway postFlyway = Flyway.configure()
                .dataSource(dataSource)
                .schemas(SCHEMA)
                .defaultSchema(SCHEMA)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .target(MIGRATION_TARGET)
                .cleanDisabled(false)
                .load();

        log.info("Migrating schema to {}", MIGRATION_TARGET);
        postFlyway.migrate();
    }

    @AfterAll
    void cleanupMigrationSchema() {
        log.info("Dropping migration schema");
        jdbcTemplate.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
    }


    @Test
    void should_preserve_offer_and_management_count_and_link_by_id() {
        final List<CredentialOffer> allOffers = credentialOfferRepository.findAll();
        final List<CredentialManagement> allManagements = credentialManagementRepository.findAll();

        assertThat(allOffers).hasSameSizeAs(DATASET);
        assertThat(allManagements).hasSameSizeAs(DATASET);

        for (CredentialOffer offer : allOffers) {
            assertThat(offer.getCredentialManagement()).isNotNull();
            assertThat(offer.getCredentialManagement().getId()).isEqualTo(offer.getId());
        }
    }

    @Test
    void should_migrate_offer_status_correctly() {
        for (UUID id : offers.keySet()) {
            final CredentialOfferData before = offers.get(id);
            final CredentialOffer offer = credentialOfferRepository.findById(id).orElseThrow();

            assertThat(offer.getCredentialStatus())
                    .isEqualTo(offerStatusMapping.get(before.offerStatus()));
        }
    }

    @Test
    void should_migrate_management_statuses_correctly() {
        for (UUID id : offers.keySet()) {
            final CredentialOfferData before = offers.get(id);
            final CredentialManagement management =
                    credentialManagementRepository.findById(id).orElseThrow();

            assertThat(management.getCredentialManagementStatus())
                    .isEqualTo(managementStatusMapping.get(before.offerStatus()));
        }
    }

    @Test
    void should_copy_and_remove_token_related_fields_correctly() {
        for (var entry : offers.entrySet()) {
            final UUID id = entry.getKey();
            final CredentialOfferData before = entry.getValue();

            final CredentialManagement management =
                    credentialManagementRepository.findById(id).orElseThrow();

            assertThat(management.getAccessToken()).isEqualTo(before.accessToken());
            assertThat(management.getRefreshToken()).isEqualTo(before.refreshToken());
            assertThat(management.getAccessTokenExpirationTimestamp())
                    .isEqualTo(before.tokenExpirationTimestamp());

            if (before.dpopKey() == null) {
                assertThat(management.getDpopKey()).isNull();
            } else {
                assertThat(management.getDpopKey())
                        .containsKeys("x", "y", "crv", "kty", "use", "kid");
            }


        }
    }

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


    void insert(CredentialOfferData data) {

        Object dpopJsonb = null;

        try {
            if (data.dpopKey() != null) {
                var dpop = new PGobject();
                dpop.setType("jsonb");
                dpop.setValue(data.dpopKey());
                dpopJsonb = dpop;
            }

            var supportedId = new PGobject();
            supportedId.setType("jsonb");
            supportedId.setValue("[\"unbound_example_sd_jwt\"]");

            jdbcTemplate.update("""
                            INSERT INTO credential_offer (
                                id,
                                nonce,
                                credential_status,
                                metadata_credential_supported_id,
                                access_token,
                                refresh_token,
                                dpop_key,
                                token_expiration_timestamp
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    data.id(),
                    UUID.randomUUID(),
                    data.offerStatus(),
                    supportedId,
                    data.accessToken(),
                    data.refreshToken(),
                    dpopJsonb,
                    data.tokenExpirationTimestamp()
            );

        } catch (Exception e) {
            throw new IllegalStateException("Invalid SQL insert test data", e);
        }
    }
}
