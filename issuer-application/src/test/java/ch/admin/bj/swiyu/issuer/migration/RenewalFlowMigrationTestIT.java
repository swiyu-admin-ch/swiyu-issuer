package ch.admin.bj.swiyu.issuer.migration;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
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
import java.nio.file.Files;
import java.nio.file.Path;
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
    private static final String PRE_MIGRATION_DATA =
            "src/test/resources/db/testdata/pre_v1_4_0__create_credential_management.sql";

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

    final int NUMBER_OFFERS = 9;

    @BeforeAll
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void migrateDatabase() throws Exception {
        log.info("Migrating schema to {}", PRE_MIGRATION_TARGET);
        Flyway.configure()
                .dataSource(dataSource)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .target(PRE_MIGRATION_TARGET)
                .load()
                .migrate();

        log.info("Loading test data");
        String sql = Files.readString(Path.of(PRE_MIGRATION_DATA));
        jdbcTemplate.execute(sql);

        log.info("Save offers before migration");
        offers = fetchOffers();

        log.info("Migrating schema to latest");
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

        assertThat(offers.size()).isEqualTo(NUMBER_OFFERS);
        assertThat(allOffers).hasSameSizeAs(offers.values());
        assertThat(allManagements).hasSameSizeAs(offers.values());

        for (CredentialOffer offer : allOffers) {
            assertThat(offer.getCredentialManagement()).isNotNull();
            assertThat(offer.getCredentialManagement().getId()).isEqualTo(offer.getId());
        }
    }

    @Test
    void should_migrate_offer_status_correctly() {
        for (UUID id : offers.keySet()) {

            final CredentialOfferData before = offers.get(id);
            final String previousStatus = before.offerStatus();

            final CredentialOffer offer =
                    credentialOfferRepository.findById(id).orElseThrow();

            final CredentialOfferStatusType expectedStatus =
                    offerStatusMapping.get(previousStatus);

            assertThat(offer.getCredentialStatus())
                    .isEqualTo(expectedStatus);
        }
    }

    @Test
    void should_migrate_management_statuses_correctly() {
        for (UUID id : offers.keySet()) {

            final CredentialOfferData before = offers.get(id);
            final String previousStatus = before.offerStatus();

            final CredentialManagement management =
                    credentialManagementRepository.findById(id).orElseThrow();

            final CredentialStatusManagementType expectedStatus =
                    managementStatusMapping.get(previousStatus);

            assertThat(management.getCredentialManagementStatus())
                    .isEqualTo(expectedStatus);
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

            if (before.dpopKey() == null) {
                assertThat(management.getDpopKey()).isNull();
            } else {
                assertThat(management.getDpopKey()).isNotNull();
                assertThat(management.getDpopKey()).containsKeys("x", "y", "crv", "kty", "use", "kid");
            }

            assertThat(management.getAccessTokenExpirationTimestamp()).isEqualTo(before.tokenExpirationTimestamp());

            final Map<String, Object> offerRow =
                    jdbcTemplate.queryForMap(
                            "SELECT * FROM credential_offer WHERE id = ?",
                            id
                    );

            assertThat(offerRow).doesNotContainKeys(
                    "access_token",
                    "refresh_token",
                    "dpop_key",
                    "token_expiration_timestamp"
            );
        }
    }

    Map<UUID, CredentialOfferData> fetchOffers() {
        return jdbcTemplate.query("""
                    SELECT id, credential_status, access_token, refresh_token, dpop_key, token_expiration_timestamp 
                    FROM credential_offer
                """, rs -> {
            final Map<UUID, CredentialOfferData> map = new HashMap<>();
            while (rs.next()) {
                final UUID id = UUID.fromString(rs.getString("id"));
                map.put(id, new CredentialOfferData(
                        id,
                        rs.getString("credential_status"),
                        rs.getObject("access_token", UUID.class),
                        rs.getObject("refresh_token", UUID.class),
                        rs.getString("dpop_key"),
                        rs.getObject("token_expiration_timestamp", Long.class)
                ));
            }
            return map;
        });
    }
}

record CredentialOfferData(
        UUID id,
        String offerStatus,
        UUID accessToken,
        UUID refreshToken,
        String dpopKey,
        Long tokenExpirationTimestamp
) {
}
