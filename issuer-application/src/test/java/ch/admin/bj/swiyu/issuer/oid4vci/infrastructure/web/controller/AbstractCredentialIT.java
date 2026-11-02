package ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createStatusList;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.linkStatusList;

/**
 * Shared base for credential integration tests: Spring Boot test setup and common persistence helpers.
 * <p>
 * Transaction handling ({@code @Transactional}) is intentionally left to the subclasses, as not all of them
 * can run inside a rolled-back transaction.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
abstract class AbstractCredentialIT {

    @Autowired
    protected MockMvc mock;
    @Autowired
    protected StatusListRepository statusListRepository;
    @Autowired
    protected CredentialOfferRepository credentialOfferRepository;
    @Autowired
    protected CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    protected CredentialManagementRepository credentialManagementRepository;

    protected void cleanDatabase() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        credentialManagementRepository.deleteAll();
        statusListRepository.deleteAll();
    }

    protected StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }

    protected StatusList saveNewStatusList() {
        return saveStatusList(createStatusList());
    }

    protected CredentialManagement saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList,
                                                             int index) {
        var credentialManagement = credentialManagementRepository.save(CredentialManagement.builder()
                .id(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialManagementStatus(CredentialStatusManagementType.INIT)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .renewalRequestCnt(0)
                .renewalResponseCnt(0)
                .build());

        offer.setCredentialManagement(credentialManagement);
        var storedOffer = credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList, index));

        credentialManagement.addCredentialOffer(storedOffer);
        return credentialManagementRepository.save(credentialManagement);
    }
}
