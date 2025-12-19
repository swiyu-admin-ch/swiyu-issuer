package ch.admin.bj.swiyu.issuer.migration;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.migration.domain.CredentialOfferV13Entity;
import ch.admin.bj.swiyu.issuer.migration.domain.CredentialOfferV13Repository;
import lombok.extern.slf4j.Slf4j;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=none"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RenewalFlowMigrationTestIT {

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
    CredentialOfferV13Repository legacyRepository;

    @Autowired
    CredentialOfferRepository credentialOfferRepository;

    @Autowired
    CredentialManagementRepository credentialManagementRepository;

    private final Map<UUID, LegacyOfferV13> offers = new HashMap<>();

    private static class LegacyOfferV13 {
        String status;
        UUID accessToken;
        UUID refreshToken;
        String dpopKey;
        Long tokenExpirationTimestamp;
    }

    private final Map<String, CredentialOfferStatusType> offerStatusMapping = Map.of(
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

    private final Map<String, CredentialStatusManagementType> managementStatusMapping = Map.of(
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

    @BeforeAll
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void migrateDatabase() {
        log.info("Migrating schema to {}", PRE_MIGRATION_TARGET);
        Flyway.configure()
                .dataSource(dataSource)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .target(PRE_MIGRATION_TARGET)
                .load()
                .migrate();

        log.info("Loading test data");
        insert("OFFERED", false, false);
        insert("CANCELLED", false, false);
        insert("IN_PROGRESS", false, false);
        insert("DEFERRED", true, true);
        insert("READY", true, false);
        insert("ISSUED", true, false);
        insert("SUSPENDED", true, false);
        insert("REVOKED", true, false);
        insert("EXPIRED", false, false);

        log.info("Migrating schema to {}", MIGRATION_TARGET);
        Flyway.configure()
                .dataSource(dataSource)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .target(MIGRATION_TARGET)
                .load()
                .migrate();
    }

    @Test
    void should_preserve_offer_and_management_count_and_link_by_id() {
        final List<CredentialOffer> allOffers = credentialOfferRepository.findAll();
        final List<CredentialManagement> allManagements = credentialManagementRepository.findAll();

        assertThat(allOffers).hasSize(offers.size());
        assertThat(allManagements).hasSize(offers.size());

        for (CredentialOffer offer : allOffers) {
            assertThat(offer.getCredentialManagement()).isNotNull();
            assertThat(offer.getCredentialManagement().getId()).isEqualTo(offer.getId());
        }
    }

    @Test
    void should_migrate_offer_status_correctly() {
        for (UUID id : offers.keySet()) {

            final LegacyOfferV13 before = offers.get(id);

            final CredentialOffer offer =
                    credentialOfferRepository.findById(id).orElseThrow();

            final CredentialOfferStatusType expected =
                    offerStatusMapping.get(before.status);

            assertThat(offer.getCredentialStatus()).isEqualTo(expected);
        }
    }

    @Test
    void should_migrate_management_statuses_correctly() {
        for (UUID id : offers.keySet()) {

            final LegacyOfferV13 before = offers.get(id);

            final CredentialManagement management =
                    credentialManagementRepository.findById(id).orElseThrow();

            final CredentialStatusManagementType expected =
                    managementStatusMapping.get(before.status);

            assertThat(management.getCredentialManagementStatus())
                    .isEqualTo(expected);
        }
    }

    @Test
    void should_copy_and_remove_token_related_fields_correctly() {
        for (Map.Entry<UUID, LegacyOfferV13> entry : offers.entrySet()) {

            final UUID id = entry.getKey();
            final LegacyOfferV13 before = entry.getValue();

            final CredentialManagement management =
                    credentialManagementRepository.findById(id).orElseThrow();

            assertThat(management.getAccessToken())
                    .isEqualTo(before.accessToken);

            assertThat(management.getRefreshToken())
                    .isEqualTo(before.refreshToken);

            assertThat(management.getAccessTokenExpirationTimestamp())
                    .isEqualTo(before.tokenExpirationTimestamp);
        }
    }

    @Test
    void should_remove_token_columns_from_credential_offer_table() {
        final List<String> columns = jdbcTemplate.queryForList(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'credential_offer'
                """,
                String.class
        );

        assertThat(columns).doesNotContain(
                "access_token",
                "refresh_token",
                "dpop_key",
                "token_expiration_timestamp"
        );
    }


    private void insert(String status, boolean withDpop, boolean withRefreshToken) {
        final UUID id = UUID.randomUUID();
        final LegacyOfferV13 legacy = new LegacyOfferV13();
        legacy.status = status;
        legacy.accessToken = UUID.randomUUID();
        legacy.refreshToken = withRefreshToken ? UUID.randomUUID() : null;
        legacy.dpopKey = withDpop ? randomDpopJson(id) : null;
        legacy.tokenExpirationTimestamp =
                Instant.now().plusSeconds(3600).getEpochSecond();

        legacyRepository.save(
                CredentialOfferV13Entity.builder()
                        .id(id)
                        .credentialStatus(status)
                        .accessToken(legacy.accessToken)
                        .refreshToken(legacy.refreshToken)
                        .dpopKey(legacy.dpopKey)
                        .tokenExpirationTimestamp(legacy.tokenExpirationTimestamp)
                        .nonce(UUID.randomUUID())
                        .build()
        );

        offers.put(id, legacy);
    }

    private static String randomDpopJson(UUID id) {
        return """
                {
                  "x": "%s",
                  "y": "%s",
                  "crv": "P-256",
                  "kty": "EC",
                  "use": "sig",
                  "kid": "holder-dpop-key-%s"
                }
                """.formatted(
                randomBase64Like(),
                randomBase64Like(),
                id
        );
    }

    private static String randomBase64Like() {
        return UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 32);
    }
}
