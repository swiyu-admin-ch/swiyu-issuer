package ch.admin.bj.swiyu.issuer.migration;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.migration.testdata.CredentialOfferData;
import ch.admin.bj.swiyu.issuer.migration.testdata.CredentialOfferTestFactory;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

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
        DATASET.forEach(this::insert);

        offers = DATASET.stream()
                .collect(Collectors.toMap(CredentialOfferData::id, it -> it));

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

        assertThat(offers.size()).isEqualTo(DATASET.size());
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

    void insert(CredentialOfferData data) {
        jdbcTemplate.update("""
                            INSERT INTO credential_offer (
                                id,
                              nonce,
                                credential_status,
                                access_token,
                                refresh_token,
                                dpop_key,
                                token_expiration_timestamp,
                                created_at,
                                last_modified_at
                            ) VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, now(), now())
                        """,
                data.id(),
                UUID.randomUUID(),
                data.offerStatus(),
                data.accessToken(),
                data.refreshToken(),
                data.dpopKey(),
                data.tokenExpirationTimestamp()
        );
    }

}



