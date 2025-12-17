package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.CredentialManagementDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.StatusResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.renewal.RenewalResponseDto;
import ch.admin.bj.swiyu.issuer.service.webhook.OfferStateChangeEvent;
import ch.admin.bj.swiyu.issuer.service.webhook.StateChangeEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer.readOfferData;
import static ch.admin.bj.swiyu.issuer.service.CredentialManagementMapper.toCredentialManagementDto;
import static ch.admin.bj.swiyu.issuer.service.CredentialManagementMapper.toCredentialStatusManagementType;
import static ch.admin.bj.swiyu.issuer.service.CredentialOfferMapper.*;
import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SDJWT_PROTECTED_CLAIMS;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.StatusResponseMapper.toStatusResponseDto;

@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialManagementService {

    private static final String STATUS_NOT_CHANGEABLE = "Tried to set %s but status is already %s";
    private static final String CREDENTIAL_NOT_FOUND = "Credential %s not found";
    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialManagementRepository credentialManagementRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final ObjectMapper objectMapper;
    private final StatusListService statusListService;
    private final IssuerMetadata issuerMetadata;
    private final ApplicationProperties applicationProperties;
    private final DataIntegrityService dataIntegrityService;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final AvailableStatusListIndexRepository availableStatusListIndexRepository;
    private final Random random = new Random();

    /**
     * Retrieve public information about a credential offer.
     *
     * <p>This method will check the credential's expiration and update its state if necessary
     * (hence the method is not read-only). It also constructs the deeplink representation
     * of the offer and maps the result to a DTO suitable for clients.</p>
     *
     * @param managementId the id of the management object
     * @return a {@link CredentialInfoResponseDto} containing credential offer information and a deeplink
     * @throws ResourceNotFoundException if no credential with the given id exists
     */
    @Transactional
    public CredentialManagementDto getCredentialOfferInformation(UUID managementId) {

        var mgmt = credentialManagementRepository.findById(managementId).orElseThrow(() -> new ResourceNotFoundException(String.format(CREDENTIAL_NOT_FOUND, managementId)));

        // TODO refactor to improve performance
        var credentialOffers = mgmt.getCredentialOffers().stream().map(this::checkOffer).collect(Collectors.toSet());

        return toCredentialManagementDto(applicationProperties, mgmt, credentialOffers);
    }

    private CredentialOffer checkOffer(CredentialOffer offer) {
        if (CredentialOfferStatusType.getExpirableStates().contains(offer.getCredentialStatus())
                && offer.hasExpirationTimeStampPassed()) {
            return expireCredentialOffer(getCredentialById(offer.getId()));
        }
        return offer;
    }

    /**
     * Update the status of a credential offer.
     *
     * <p>Loads the credential with a pessimistic write lock, converts the incoming
     * {@code requestedNewStatus} DTO to the internal {@link CredentialOfferStatusType},
     * performs the status transition and returns a DTO with the updated state.</p>
     *
     * @param credentialManagementId the id of the credential offer to update
     * @param requestedNewStatus     the requested new status DTO
     * @return an {@link UpdateStatusResponseDto} describing the updated credential status
     * @throws ResourceNotFoundException if no credential offer with the given id exists
     * @throws BadRequestException       if the requested transition is invalid or cannot be performed
     */
    @Transactional
    public UpdateStatusResponseDto updateCredentialStatus(@NotNull UUID credentialManagementId,
                                                          @NotNull UpdateCredentialStatusRequestTypeDto requestedNewStatus) {

        var mgmt = getCredentialManagement(credentialManagementId);

        if (mgmt.isPreIssuanceProcess()) {
            return handlePreIssuanceStatusChange(mgmt, requestedNewStatus);
        }

        return this.handlePostIssuanceStatusChangeForOffer(mgmt, requestedNewStatus);
    }

    /**
     * Retrieve the current status of a credential offer.
     *
     * <p>Loads the credential and returns a mapped {@link StatusResponseDto}. This method is
     * transactional and not read-only because loading the credential may update its state when
     * the offer has expired.</p>
     *
     * @param credentialManagementId the id of the credential offer
     * @return the {@link StatusResponseDto} representing the credential's current status
     * @throws ResourceNotFoundException if no credential with the given id exists
     */
    @Transactional
    public StatusResponseDto getCredentialStatus(UUID credentialManagementId) {

        CredentialManagement credentialManagement = getCredentialManagement(credentialManagementId);

        if (credentialManagement.isPreIssuanceProcess()) {
            var credentialOffer = credentialManagement.getCredentialOffers()
                    .stream()
                    .findFirst()
                    .orElseThrow(() -> new ResourceNotFoundException("No credential offer found for management id %s".formatted(credentialManagementId)));

            return toStatusResponseDto(credentialOffer);
        }

        return toStatusResponseDto(credentialManagement);
    }

    @Transactional
    /**
     * Create a credential offer and return its deeplink.
     *
     * <p>Validates the provided request, determines the issuance batch size from
     * the issuer metadata, creates and persists a new credential offer and then
     * builds the deeplink representation for the created offer.</p>
     *
     * @param request the create credential offer request
     * @return a {@link CredentialWithDeeplinkResponseDto} containing the created credential offer and its deeplink
     * @throws BadRequestException if the request is invalid or referenced resources cannot be resolved
     * @throws IllegalStateException if the credential configuration format is unsupported
     * @throws JsonException if the created credential offer cannot be serialized to build the deeplink
     */
    public CredentialWithDeeplinkResponseDto createCredentialOfferAndGetDeeplink(@Valid CreateCredentialOfferRequestDto request) {

        validateCredentialOfferCreateRequest(request);
        var credentialMgmt = this.createCredentialOffer(request);
        var credentialOffer = credentialMgmt.getCredentialOffers().stream()
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No credential offer created"));

        return CredentialOfferMapper.toCredentialWithDeeplinkResponseDto(applicationProperties, credentialMgmt, credentialOffer);
    }

    public CredentialOffer createInitialCredentialOfferForRenewal(CredentialManagement credentialManagement) {
        var offer = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .nonce(UUID.randomUUID())
                        .credentialManagement(credentialManagement)
                        .credentialStatus(CredentialOfferStatusType.REQUESTED)
                        .build());

        credentialManagement.addCredentialOffer(offer);

        credentialManagement.setRenewalRequestCnt(credentialManagement.getRenewalRequestCnt() + 1);

        credentialManagementRepository.save(credentialManagement);

        return offer;
    }

    /**
     * Updates an existing {@link CredentialOffer} using data from a renewal response.
     *
     * <p>Constructs a temporary {@link CreateCredentialOfferRequestDto} from the provided
     * {@code request}, validates the constructed request against issuer metadata and claim
     * constraints, resolves the referenced status lists, applies the refreshed data to
     * {@code existingOffer}, persists the updated offer and registers its status list indexes.</p>
     *
     * @param request       the renewal response containing new offer data (must be valid)
     * @param existingOffer the persisted credential offer to update
     * @return the persisted {@link CredentialOffer} after applying the renewal data
     * @throws BadRequestException   if validation fails or referenced status lists cannot be resolved
     * @throws IllegalStateException if the credential configuration format is unsupported
     */
    public CredentialOffer updateOfferFromRenewalResponse(@Valid RenewalResponseDto request, CredentialOffer existingOffer) {

        CreateCredentialOfferRequestDto newOffer = toOfferFromRenewal(request);

        validateCredentialOfferCreateRequest(newOffer);

        var statusLists = checkStatusLists(newOffer);

        existingOffer.setMetadataCredentialSupportedId(newOffer.getMetadataCredentialSupportedId());
        existingOffer.setOfferData(readOfferData(newOffer.getCredentialSubjectData()));
        existingOffer.setCredentialValidFrom(newOffer.getCredentialValidFrom());
        existingOffer.setCredentialValidUntil(newOffer.getCredentialValidUntil());
        existingOffer.setCredentialMetadata(toCredentialOfferMetadataDto(newOffer.getCredentialMetadata()));
        existingOffer.setConfigurationOverride(toConfigurationOverride(newOffer.getConfigurationOverride()));
        existingOffer.setMetadataTenantId(applicationProperties.isSignedMetadataEnabled() ? UUID.randomUUID() : null);

        CredentialOffer entity = credentialOfferRepository.save(existingOffer);

        saveStatusList(statusLists, entity.getId());

        return entity;
    }

    /**
     * Scheduled job that expires credential offers whose expiration timestamp has passed.
     *
     * <p>Finds offers in expirable states with an offer expiration timestamp less than the
     * current time, updates their status to {@link CredentialOfferStatusType#EXPIRED} and triggers
     * the usual status-change processing (including deletion of associated person data).
     * Runs according to the configured {@code application.offer-expiration-interval} and uses
     * a distributed lock ("expireOffers") to avoid concurrent execution across instances.
     * Executes within a transaction.</p>
     */
    @Scheduled(initialDelay = 0, fixedDelayString = "${application.offer-expiration-interval}")
    @SchedulerLock(name = "expireOffers")
    @Transactional
    public void expireOffers() {
        var expireStates = CredentialOfferStatusType.getExpirableStates();
        var expireTimeStamp = Instant.now().getEpochSecond();
        log.info("Expiring {} offers", credentialOfferRepository
                .countByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp));
        var expiredOffers = credentialOfferRepository
                .findByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp);
        expiredOffers.forEach(this::expireCredentialOffer);
    }

    /**
     * Update the offer data for a deferred credential.
     *
     * <p>Loads the credential offer with a pessimistic write lock and verifies that the
     * offer is a deferred offer currently in the {@code DEFERRED} state. If the check
     * fails a {@link BadRequestException} is thrown. Further processing (validation and
     * persisting the updated offer data) continues after this method's initial checks.</p>
     *
     * @param credentialManagementId the id of the credential management offer to update
     * @param offerDataMap           the credential subject data to apply to the deferred offer
     * @return an {@link UpdateStatusResponseDto} describing the updated credential status
     * @throws ResourceNotFoundException if no credential offer with the given id exists
     * @throws BadRequestException       if the credential is not deferred or has an incorrect status
     */
    @Transactional
    public UpdateStatusResponseDto updateOfferDataForDeferred(@NotNull UUID credentialManagementId, Map<String, Object> offerDataMap) {
        var mgmt = getCredentialManagement(credentialManagementId);
        var storedCredentialOffer = mgmt.getCredentialOffers().stream().filter(o -> o.isDeferredOffer()).findFirst().orElseThrow(() -> new BadRequestException("Credential is either not deferred or has an incorrect status, cannot update offer data"));

        if (!storedCredentialOffer.isDeferredOffer()
                && storedCredentialOffer.getCredentialStatus() == CredentialOfferStatusType.DEFERRED) {
            throw new BadRequestException(
                    "Credential is either not deferred or has an incorrect status, cannot update offer data");
        }

        // check if offerData matches the expected metadata claims
        var offerData = readOfferData(offerDataMap);

        var credentialOfferMetadata = storedCredentialOffer.getMetadataCredentialSupportedId().getFirst();

        var credentialConfig = issuerMetadata.getCredentialConfigurationById(credentialOfferMetadata);

        validateCredentialRequestOfferData(offerData, true, credentialConfig);

        // update the offer data
        storedCredentialOffer.markAsReadyForIssuance(offerData);
        credentialOfferRepository.save(storedCredentialOffer);

        return toUpdateStatusResponseDto(storedCredentialOffer);
    }

    /**
     * Retrieve the {@link ConfigurationOverride} for a credential offer identified by the given tenant id.
     *
     * @param tenantId the tenant id associated with the credential offer
     * @return the {@link ConfigurationOverride} of the found credential offer, or {@code null} if no override is set
     * @throws ResourceNotFoundException if no credential offer exists for the provided tenant id
     */
    @Transactional
    public ConfigurationOverride getConfigurationOverrideByTenantId(UUID tenantId) {
        var offer = credentialOfferRepository.findByMetadataTenantId(tenantId)
                .orElseThrow(() -> new ResourceNotFoundException("No credential offer found for tenant %s".formatted(tenantId)));

        return offer.getConfigurationOverride();
    }

    private CredentialManagement getCredentialManagement(UUID managementId) {
        var mgmt = this.credentialManagementRepository.findById(managementId)
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Credential Management %s not found", managementId)));

        mgmt.getCredentialOffers().forEach(offer -> {
            // Make sure only offer is returned if it is not expired
            if (CredentialOfferStatusType.getExpirableStates().contains(offer.getCredentialStatus())
                    && offer.hasExpirationTimeStampPassed()) {
                expireCredentialOffer(getCredentialById(offer.getId()));
            }
        });

        return credentialManagementRepository.save(mgmt);
    }

    /**
     * Validates a credential offer create request, doing sanity checks with
     * configurations
     *
     * @param createCredentialRequest the create credential request to be validated
     */
    private void validateCredentialOfferCreateRequest(@Valid CreateCredentialOfferRequestDto createCredentialRequest) {
        var credentialOfferMetadata = createCredentialRequest.getMetadataCredentialSupportedId().getFirst();

        // Date checks, if exists
        validateOfferedCredentialValiditySpan(createCredentialRequest);
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(credentialOfferMetadata);

        // Check if credential format is supported otherwise throw error
        if (!List.of("vc+sd-jwt", "dc+sd-jwt").contains(credentialConfiguration.getFormat())) {
            throw new IllegalStateException("Unsupported credential configuration format %s, only supporting dc+sd-jwt"
                    .formatted(credentialConfiguration.getFormat()));
        }

        var metadata = createCredentialRequest.getCredentialMetadata();
        var isDeferredRequest = (metadata != null && Boolean.TRUE.equals(metadata.deferred()));
        var offerData = readOfferData(createCredentialRequest.getCredentialSubjectData());

        validateCredentialRequestOfferData(offerData, isDeferredRequest, credentialConfiguration);
    }

    /**
     * Checks the offerData for claims not expected in the metadata
     */
    private void validateClaimsSurplus(Set<String> metadataClaims, Map<String, Object> offerData) {
        var surplusOfferedClaims = new HashSet<>(offerData.keySet());
        surplusOfferedClaims.removeAll(metadataClaims);

        if (!surplusOfferedClaims.isEmpty()) {
            throw new BadRequestException(
                    "Unexpected credential claims found! %s".formatted(String.join(",", surplusOfferedClaims)));
        }
    }

    /**
     * checks if all claims published as mandatory in the metadata are present in
     * the offer
     */
    private void validateClaimsMissing(Set<String> metadataClaims, Map<String, Object> offerData,
                                       CredentialConfiguration credentialConfiguration) {
        var missingOfferedClaims = new HashSet<>(metadataClaims);
        missingOfferedClaims.removeAll(offerData.keySet());
        // Remove optional claims
        missingOfferedClaims.removeIf(claimKey -> !credentialConfiguration.getClaims().get(claimKey).isMandatory());
        if (!missingOfferedClaims.isEmpty()) {
            throw new BadRequestException(
                    "Mandatory credential claims are missing! %s".formatted(String.join(",", missingOfferedClaims)));
        }
    }

    private void validateOfferedCredentialValiditySpan(@Valid CreateCredentialOfferRequestDto credentialOffer) {
        var validUntil = credentialOffer.getCredentialValidUntil();
        if (validUntil != null) {
            if (validUntil.isBefore(Instant.now())) {
                throw new BadRequestException(
                        "Credential is already expired (would only be valid until %s, server time is %s)"
                                .formatted(validUntil, Instant.now()));
            }
            var validFrom = credentialOffer.getCredentialValidFrom();
            if (validFrom != null && validFrom.isAfter(validUntil)) {
                throw new BadRequestException(
                        "Credential would never be valid - Valid from %s until %s".formatted(validFrom, validUntil));
            }
        }
    }

    private CredentialManagement createCredentialOffer(CreateCredentialOfferRequestDto requestDto) {
        var expiration = Instant.now().plusSeconds(requestDto.getOfferValiditySeconds() > 0
                ? requestDto.getOfferValiditySeconds()
                : applicationProperties.getOfferValidity());
        // Check if credentialSubjectData contains protected claims
        var offerData = readOfferData(requestDto.getCredentialSubjectData());

        // Get used status lists and ensure they are managed by the issuer
        var statusLists = checkStatusLists(requestDto);

        CredentialManagement credentialManagement = credentialManagementRepository.save(CredentialManagement.builder()
                .id(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialManagementStatus(CredentialStatusManagementType.INIT)
                .renewalResponseCnt(0)
                .renewalRequestCnt(0)
                .build());

        CredentialOffer entity = credentialOfferRepository.save(CredentialOffer.builder()
                .credentialStatus(CredentialOfferStatusType.OFFERED)
                .metadataCredentialSupportedId(requestDto.getMetadataCredentialSupportedId())
                .preAuthorizedCode(UUID.randomUUID())
                .offerData(offerData)
                .offerExpirationTimestamp(expiration.getEpochSecond())
                .nonce(UUID.randomUUID())
                .credentialValidFrom(requestDto.getCredentialValidFrom())
                .deferredOfferValiditySeconds(requestDto.getDeferredOfferValiditySeconds())
                .credentialValidUntil(requestDto.getCredentialValidUntil())
                .credentialMetadata(toCredentialOfferMetadataDto(requestDto.getCredentialMetadata()))
                .configurationOverride(toConfigurationOverride(requestDto.getConfigurationOverride()))
                .metadataTenantId(applicationProperties.isSignedMetadataEnabled() ? UUID.randomUUID() : null)
                .credentialManagement(credentialManagement)
                .build());

        entity = this.credentialOfferRepository.save(entity);
        credentialManagement.addCredentialOffer(entity);

        var newCredentialManagement = credentialManagementRepository.save(credentialManagement);
        log.debug("Created Credential offer {} valid until {}", entity.getId(), expiration.toEpochMilli());

        var offerId = entity.getId();
        saveStatusList(statusLists, offerId);

        return newCredentialManagement;
    }

    private void saveStatusList(List<StatusList> statusLists, UUID credentialOfferId) {
        for (StatusList statusList : statusLists) {
            Set<Integer> randomIndexes = getRandomIndexes(issuerMetadata.getIssuanceBatchSize(), statusList);
            // Create Status List entries
            var offerStatuses = randomIndexes.stream().map(freeIndex -> {
                var offerStatusKey = CredentialOfferStatusKey.builder()
                        .offerId(credentialOfferId)
                        .statusListId(statusList.getId())
                        .index(freeIndex)
                        .build();
                log.debug("Credential offer {} uses status list {} indexes {}", credentialOfferId, statusList.getUri(), freeIndex);
                return CredentialOfferStatus.builder()
                        .id(offerStatusKey)
                        .build();
            }).toList();
            credentialOfferStatusRepository.saveAll(offerStatuses);
        }
    }

    private Set<Integer> getRandomIndexes(int issuanceBatchSize, StatusList statusList) {
        // Find all free indexes for this status list
        var freeIndexes = availableStatusListIndexRepository.findById(statusList.getUri())
                .orElseThrow(() -> new BadRequestException("No status indexes remain in status list %s to create credential offer".formatted(statusList.getUri())))
                .getFreeIndexes();
        if (freeIndexes.size() < issuanceBatchSize) {
            throw new BadRequestException("Too few status indexes remain in status list %s to create credential offer".formatted(statusList.getUri()));
        }
        // Random sample free indexes without repetitions
        Set<Integer> sampledNumbers = new LinkedHashSet<>();
        while (sampledNumbers.size() < issuanceBatchSize) {
            sampledNumbers.add(freeIndexes.get(random.nextInt(freeIndexes.size())));
        }
        return sampledNumbers;
    }


    /**
     * The issuer did (iss) of VCs and the linked status lists have to be the same or verifications will fail.
     * <p>
     * Developer Note: Since Token Status List Draft 04 requirement for matching iss claim in Referenced Token and Status List Token has been removed
     * The wallet and verifier must be first migrated before this check can be removed
     */
    @Deprecated(since = "Token Status List Draft 04")
    private void ensureMatchingIssuerDids(CreateCredentialOfferRequestDto requestDto, List<StatusList> statusLists) {
        // Ensure that chosen stats lists issuer dids match the vc issuer did
        var override = requestDto.getConfigurationOverride();
        String issuerDid;
        if (override != null && StringUtils.isNotEmpty(override.issuerDid())) {
            issuerDid = override.issuerDid();
        } else {
            issuerDid = applicationProperties.getIssuerId();
        }

        var mismatchingStatusLists = statusLists.stream().filter(statusList -> !Objects.requireNonNullElseGet(statusList.getConfigurationOverride().issuerDid(), applicationProperties::getIssuerId).equals(issuerDid)).toList();
        if (!mismatchingStatusLists.isEmpty()) {
            throw new BadRequestException(String.format("Status List issuer did is not the same as credential issuer did for %s",
                    mismatchingStatusLists.stream().map(StatusList::getUri).collect(Collectors.joining(", "))));
        }
    }

    private CredentialOffer expireCredentialOffer(CredentialOffer credential) {
        var currentStatus = credential.getCredentialStatus();

        if (credential.getCredentialStatus().isTerminalState()) {
            throw new BadRequestException(String.format(STATUS_NOT_CHANGEABLE, CredentialOfferStatusType.EXPIRED, currentStatus));
        }

        credential.expire();

        var updatedCredential = this.credentialOfferRepository.save(credential);

        produceOfferStateChangeEvent(credential.getCredentialManagement().getId(), credential.getId(), credential.getCredentialStatus());

        return updatedCredential;
    }

    /**
     * Load a credential by id while acquiring a database lock to prevent modifications.
     * The repository method `findByIdForUpdate`uses a pessimistic lock.
     *
     * @param credentialId the credential identifier
     * @return the locked {@link CredentialOffer}
     * @throws ResourceNotFoundException if no credential with the given id exists
     */
    private CredentialOffer getCredentialById(UUID credentialId) {
        return this.credentialOfferRepository.findByIdForUpdate(credentialId)
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format(CREDENTIAL_NOT_FOUND, credentialId)));
    }


    /**
     * Handles status changes before issuance (status cancelled, ready and expired)
     */
    private void handlePreIssuanceStatusChange(CredentialOffer credential,
                                               CredentialOfferStatusType currentStatus,
                                               CredentialOfferStatusType newStatus) {

        // if the new status is READY, then we can only set it if the old status was
        // deferred
        if (currentStatus == CredentialOfferStatusType.DEFERRED && newStatus == CredentialOfferStatusType.READY) {
            credential.changeStatus(CredentialOfferStatusType.READY);
            return;
        }

        if (newStatus == CredentialOfferStatusType.CANCELLED) {
            credential.cancel();
            return;
        }

        throw new BadRequestException(String.format(
                "Illegal state transition - Status cannot be updated from %s to %s", currentStatus, newStatus));
    }

    /**
     * Handles status changes after issuance (status suspended, revoked and issued)
     *
     * @return
     */
    private List<UUID> handlePostIssuanceStatusChange(CredentialManagement mgmt, CredentialStatusManagementType newStatus) {

        var affectedOffers = mgmt.getCredentialOffers().stream().map(CredentialOffer::getId).toList();

        final Set<CredentialOfferStatus> offerStatusSet = credentialOfferStatusRepository
                .findByOfferIdIn(affectedOffers);

        if (offerStatusSet.isEmpty()) {
            throw new BadRequestException(
                    "No associated status lists found. Can not set a status to an already issued credential");
        }

        return switch (newStatus) {
            case REVOKED -> statusListService.revoke(offerStatusSet);
            case SUSPENDED -> statusListService.suspend(offerStatusSet);
            case ISSUED -> statusListService.revalidate(offerStatusSet);
            default -> throw new BadRequestException(String.format(
                    "Illegal state transition - Status cannot be updated for %s to %s",
                    mgmt.getId(), newStatus));
        };
    }

    private void produceStateChangeEvent(UUID credentialOfferId, CredentialStatusManagementType state) {
        var stateChangeEvent = new StateChangeEvent(
                credentialOfferId,
                state
        );
        applicationEventPublisher.publishEvent(stateChangeEvent);
    }

    private void produceOfferStateChangeEvent(UUID credentialManagementId, UUID credentialOfferId, CredentialOfferStatusType state) {
        var stateChangeEvent = new OfferStateChangeEvent(
                credentialManagementId,
                credentialOfferId,
                state
        );
        applicationEventPublisher.publishEvent(stateChangeEvent);
    }

    private void validateCredentialRequestOfferData(Map<String, Object> offerData,
                                                    boolean isDeferredRequest,
                                                    CredentialConfiguration credentialConfiguration) {

        // with deferred requests the offer data can be empty initially if the data is set it must be validated
        if (isDeferredRequest && CollectionUtils.isEmpty(offerData)) {
            return;
        }

        // data cannot be empty
        if (CollectionUtils.isEmpty(offerData)) {
            throw new BadRequestException("Credential claims (credential subject data) is missing!");
        }

        var validatedOfferData = dataIntegrityService.getVerifiedOfferData(offerData, null);

        // check if credentialSubjectData contains protected claims
        List<String> reservedClaims = new ArrayList<>(validatedOfferData.keySet().stream()
                .filter(SDJWT_PROTECTED_CLAIMS::contains)
                .toList());

        if (!reservedClaims.isEmpty()) {
            throw new BadRequestException(
                    "The following claims are not allowed in the credentialSubjectData: " + reservedClaims);
        }

        var metadataClaims = Optional.ofNullable(credentialConfiguration.getClaims()).orElseGet(HashMap::new).keySet();

        validateClaimsMissing(metadataClaims, validatedOfferData, credentialConfiguration);
        validateClaimsSurplus(metadataClaims, validatedOfferData);
    }

    private List<StatusList> checkStatusLists(CreateCredentialOfferRequestDto newOffer) {
        var statusListUris = newOffer.getStatusLists();
        var statusLists = statusListService.findByUriIn(statusListUris);
        if (statusLists.size() != newOffer.getStatusLists().size()) {
            throw new BadRequestException(String.format("Could not resolve all provided status lists, only found %s",
                    statusLists.stream().map(StatusList::getUri).collect(Collectors.joining(", "))));
        }

        ensureMatchingIssuerDids(newOffer, statusLists);

        return statusLists;
    }

    private UpdateStatusResponseDto handlePostIssuanceStatusChangeForOffer(CredentialManagement mgmt, UpdateCredentialStatusRequestTypeDto requestedNewStatus) {

        var newStatus = toCredentialStatusManagementType(requestedNewStatus);

        var currentStatus = mgmt.getCredentialManagementStatus();

        // Ignore no status changes and return. This needs to be checked first to
        // prevent unnecessary errors
        if (currentStatus == newStatus) {
            return CredentialManagementMapper.toUpdateStatusResponseDto(mgmt, null);
        }

        // status is already in a terminal state and cannot be changed
        if (currentStatus == CredentialStatusManagementType.REVOKED) {
            throw new BadRequestException(String.format(STATUS_NOT_CHANGEABLE, newStatus, currentStatus));
        }

        // get all
        var statusList = handlePostIssuanceStatusChange(mgmt, newStatus);

        log.debug("Updating credential management {} from {} to {}", mgmt.getId(), currentStatus, newStatus);

        mgmt.setCredentialManagementStatus(newStatus);

        var updatedMgmt = this.credentialManagementRepository.save(mgmt);

        produceStateChangeEvent(updatedMgmt.getId(), newStatus);

        return CredentialManagementMapper.toUpdateStatusResponseDto(updatedMgmt, statusList);
    }

    private UpdateStatusResponseDto handlePreIssuanceStatusChange(CredentialManagement mgmt, UpdateCredentialStatusRequestTypeDto requestedNewStatus) {
        var newStatus = toCredentialStatusType(requestedNewStatus);

        var credentialOfferForUpdate = mgmt.getCredentialOffers().stream()
                .findFirst()
                .orElseThrow(() -> new BadRequestException("Credential offer is not processable"));


        var currentStatus = credentialOfferForUpdate.getCredentialStatus();

        // Ignore no status changes and return. This needs to be checked first to
        // prevent unnecessary errors
        if (currentStatus == newStatus) {
            return toUpdateStatusResponseDto(credentialOfferForUpdate);
        }

        // status is already in a terminal state and cannot be changed
        if (currentStatus.isTerminalState()) {
            throw new BadRequestException(String.format(STATUS_NOT_CHANGEABLE, newStatus, currentStatus));
        }

        if (newStatus == CredentialOfferStatusType.EXPIRED) {
            credentialOfferForUpdate.expire();
        }

        handlePreIssuanceStatusChange(credentialOfferForUpdate, currentStatus, newStatus);

        log.debug("Updating credential {} from {} to {}", credentialOfferForUpdate.getId(), currentStatus, newStatus);

        var updatedCredentialOffer = this.credentialOfferRepository.save(credentialOfferForUpdate);

        produceOfferStateChangeEvent(credentialOfferForUpdate.getCredentialManagement().getId(), updatedCredentialOffer.getId(), newStatus);

        return toUpdateStatusResponseDto(credentialOfferForUpdate);
    }

    private CreateCredentialOfferRequestDto toOfferFromRenewal(RenewalResponseDto request) {
        return CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(request.metadataCredentialSupportedId())
                .credentialSubjectData(request.credentialSubjectData())
                .credentialMetadata(request.credentialMetadata())
                .credentialValidUntil(request.credentialValidUntil())
                .credentialValidFrom(request.credentialValidFrom())
                .statusLists(request.statusLists())
                .build();
    }
}