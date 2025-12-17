package ch.admin.bj.swiyu.issuer.migration;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class RenewalFlowMigrationTestIT {

    private static final Logger log = LoggerFactory.getLogger(RenewalFlowMigrationTestIT.class);

    private static final List<String> MIGRATION_LOCATIONS = List.of(
            "classpath:db/migration/common",
            "classpath:db/migration/postgres"
    );

    private static final String PRE_MIGRATION_TARGET = "1.3.0";
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

    @BeforeEach
    void migrateDatabase() throws Exception {
        log.info("Cleaning database");

        Flyway.configure()
                .dataSource(dataSource)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .cleanDisabled(false)
                .load()
                .clean();

        log.info("Migrating schema to {}", PRE_MIGRATION_TARGET);

        Flyway.configure()
                .dataSource(dataSource)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .target(PRE_MIGRATION_TARGET)
                .load()
                .migrate();

        log.info("Loading legacy data");

        String sql = Files.readString(Path.of(PRE_MIGRATION_DATA));
        jdbcTemplate.execute(sql);

        log.info("Migrating schema to latest");

        Flyway.configure()
                .dataSource(dataSource)
                .locations(MIGRATION_LOCATIONS.toArray(String[]::new))
                .load()
                .migrate();
    }

    @Test
    @Transactional
    void should_migrate_offer_status_into_credential_management() {
        List<CredentialOffer> offers = credentialOfferRepository.findAll();
        assertThat(offers).isNotEmpty();

        CredentialOffer offer = offers.getFirst();
        UUID offerId = offer.getId();

        Optional<CredentialManagement> managementOpt =
                credentialManagementRepository.findById(offerId);

        assertThat(managementOpt).isPresent();

        CredentialManagement management = managementOpt.get();

        assertThat(management.getCredentialManagementStatus()).isNotNull();
        assertThat(offer.getCredentialManagement()).isNotNull();
        assertThat(offer.getCredentialManagement().getId()).isEqualTo(management.getId());
    }
}
