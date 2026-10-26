package ch.admin.bj.swiyu.issuer.pact;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListConfigDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.service.management.CredentialManagementService;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListOrchestrator;

import java.util.List;
import java.util.Map;

/**
 * Prepares persisted Pact states through the real issuer services. The provider test invokes cleanup
 * before each interaction; all repositories belong to its isolated Testcontainers database.
 */
class IssuerManagementPactFixture {

    private final CredentialManagementService credentialManagementService;
    private final StatusListOrchestrator statusListOrchestrator;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialManagementRepository credentialManagementRepository;
    private final StatusListRepository statusListRepository;

    IssuerManagementPactFixture(final CredentialManagementService credentialManagementService,
                               final StatusListOrchestrator statusListOrchestrator,
                               final CredentialOfferStatusRepository credentialOfferStatusRepository,
                               final CredentialOfferRepository credentialOfferRepository,
                               final CredentialManagementRepository credentialManagementRepository,
                               final StatusListRepository statusListRepository) {
        this.credentialManagementService = credentialManagementService;
        this.statusListOrchestrator = statusListOrchestrator;
        this.credentialOfferStatusRepository = credentialOfferStatusRepository;
        this.credentialOfferRepository = credentialOfferRepository;
        this.credentialManagementRepository = credentialManagementRepository;
        this.statusListRepository = statusListRepository;
    }

    Map<String, Object> createStatusList() {
        final var request = StatusListCreateDto.builder()
                .maxLength(1000)
                .config(StatusListConfigDto.builder().bits(2).build())
                .build();
        final var statusList = statusListOrchestrator.createStatusList(request);
        return Map.of("statusListId", statusList.getId().toString());
    }

    Map<String, Object> createCredentialManagement(final boolean deferred) {
        final var request = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(Map.of(
                        "firstName", "John",
                        "lastName", "Doe",
                        "dateOfBirth", "2000-01-01"))
                .credentialMetadata(new CredentialOfferMetadataDto(deferred, null, null))
                .offerValiditySeconds(86400)
                .statusLists(List.of())
                .build();
        final var response = credentialManagementService.createCredentialOfferAndGetDeeplink(request);

        if (deferred) {
            final var offer = credentialOfferRepository.findById(response.getOfferId()).orElseThrow();
            offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.DEFERRED);
            credentialOfferRepository.saveAndFlush(offer);
        }

        return Map.of(
                "managementId", response.getManagementId().toString(),
                "offerId", response.getOfferId().toString());
    }

    void cleanDatabase() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        credentialManagementRepository.deleteAll();
        statusListRepository.deleteAll();
    }
}
