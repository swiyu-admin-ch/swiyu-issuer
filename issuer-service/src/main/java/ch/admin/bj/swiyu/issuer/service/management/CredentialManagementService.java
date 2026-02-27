package ch.admin.bj.swiyu.issuer.service.management;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.CredentialManagementDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.StatusResponseDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig.CredentialManagementEvent;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.CredentialStateService;
import ch.admin.bj.swiyu.issuer.service.offer.CredentialOfferMapper;
import ch.admin.bj.swiyu.issuer.service.offer.CredentialOfferValidationService;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.renewal.RenewalResponseDto;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListOrchestrator;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer.readOfferData;
import static ch.admin.bj.swiyu.issuer.service.management.CredentialManagementMapper.*;
import static ch.admin.bj.swiyu.issuer.service.offer.CredentialOfferMapper.toUpdateStatusResponseDto;
import static ch.admin.bj.swiyu.issuer.service.offer.CredentialOfferMapper.*;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.StatusResponseMapper.toStatusResponseDto;

/**
 * Service responsible for coordinating credential management operations.
 *
 * <p>
 * This service acts as a facade, orchestrating calls to specialized services
 * for validation, state management, persistence, and status list operations.
 * </p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialManagementService {

    private static final String STATUS_NOT_CHANGEABLE = "Tried to set %s but status is already %s";

    private final IssuerMetadata issuerMetadata;
    private final ApplicationProperties applicationProperties;

    private final CredentialOfferValidationService validationService;
    private final CredentialStateService stateService;
    private final CredentialPersistenceService persistenceService;
    private final StatusListOrchestrator statusListOrchestrator;

    /**
     * Retrieve public information about a credential offer.
     *
     * <p>
     * This method will check the credential's expiration and update its state if
     * necessary
     * (hence the method is not read-only). It also constructs the deeplink
     * representation
     * of the offer and maps the result to a DTO suitable for clients.
     * </p>
     *
     * @param managementId the id of the management object
     * @return a {@link CredentialInfoResponseDto} containing credential offer
     *         information and a deeplink
     * @throws ResourceNotFoundException if no credential with the given id exists
     */
    @Transactional
    public CredentialManagementDto getCredentialOfferInformation(UUID managementId) {
        var mgmt = persistenceService.findCredentialManagementById(managementId);

        // Check and expire offers if needed
        var credentialOffers = mgmt.getCredentialOffers().stream()
                .map(this::checkAndExpireOffer)
                .collect(Collectors.toSet());
        try {
            return toCredentialManagementDto(applicationProperties, mgmt, credentialOffers);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to parse management object with DPoP key", e);
        }
    }

    /**
     * Retrieve public information about a specific credential offer.
     *
     * <p>
     * This method will check the credential's expiration and update its state if
     * necessary
     * (hence the method is not read-only). It also constructs the deeplink
     * representation
     * of the offer and maps the result to a DTO suitable for clients.
     * </p>
     *
     * @param managementId the id of the management object
     * @param offerId      the id of the offer object
     * @return a {@link CredentialInfoResponseDto} containing credential offer
     *         information and a deeplink
     * @throws ResourceNotFoundException if no credential with the given id exists
     */
    @Transactional
    public CredentialInfoResponseDto getSpecificCredentialOfferInformation(UUID managementId, UUID offerId) {
        var offer = getCredentialOfferWithExpirationCheck(offerId);
        if (!offer.getCredentialManagement().getId().equals(managementId)) {
            throw new ResourceNotFoundException("No offer with offerId %s found".formatted(offerId));
        }

        return toCredentialInfoResponseDto(offer, applicationProperties);
    }

    /**
     * Checks if an offer has expired and updates its state if necessary.
     *
     * @param offer the credential offer to check
     * @return the (potentially updated) credential offer
     */
    private CredentialOffer checkAndExpireOffer(CredentialOffer offer) {
        if (CredentialOfferStatusType.getExpirableStates().contains(offer.getCredentialStatus())
                && offer.hasExpirationTimeStampPassed()) {
            return expireCredentialOffer(offer);
        }
        return offer;
    }

    /**
     * Update the status of a credential offer.
     *
     * <p>
     * Loads the credential with a pessimistic write lock, converts the incoming
     * {@code requestedNewStatus} DTO to the internal
     * {@link CredentialOfferStatusType},
     * performs the status transition and returns a DTO with the updated state.
     * </p>
     *
     * <p>
     * In this request, a webhook is also triggered. Through this webhook, the state
     * of the Offer or the
     * Management Offer is sent back to the Business Issuer. This depends on the
     * current state of the Offer.
     * If the Management Offer is in a pre-issuance state (INIT), the webhook is
     * first triggered with the status
     * change of the Offer (in this case, there can only be one).
     * Afterwards, during the post-issuance process, a possible status change of the
     * Management Offer is processed.
     * If the status changes, the Management Offer status transition is then sent
     * via webhook.
     * </p>
     *
     * @param credentialManagementId the id of the credential offer to update
     * @param requestedNewStatus     the requested new status DTO
     * @return an {@link UpdateStatusResponseDto} describing the updated credential
     *         status
     * @throws ResourceNotFoundException if no credential offer with the given id
     *                                   exists
     * @throws BadRequestException       if the requested transition is invalid or
     *                                   cannot be performed
     */
    @Transactional
    public UpdateStatusResponseDto updateCredentialStatus(
            @NotNull UUID credentialManagementId,
            @NotNull UpdateCredentialStatusRequestTypeDto requestedNewStatus) {

        var mgmt = getCredentialManagementWithExpirationCheck(credentialManagementId);

        var managementEvent = toCredentialManagementEvent(requestedNewStatus);
        var offerEvent = toCredentialOfferEvent(requestedNewStatus);

        validateIssuanceNotSkipped(managementEvent, mgmt);

        validateReadyOnlyInInit(offerEvent, mgmt);

        return stateService.handleStatusChange(
                mgmt, managementEvent, offerEvent);
    }

    /**
     * Validates that only READY event is allowed in INIT state of credential
     * management.
     * 
     * @param offerEvent
     * @param mgmt
     */
    private static void validateReadyOnlyInInit(CredentialStateMachineConfig.CredentialOfferEvent offerEvent,
            CredentialManagement mgmt) {
        if (offerEvent == CredentialStateMachineConfig.CredentialOfferEvent.READY
                && mgmt.getCredentialManagementStatus() != CredentialStatusManagementType.INIT) {
            throw new IllegalStateException(
                    "Only READY status is allowed in INIT state of credential management. Just " +
                            "in deferred offer scenario. In this case, the management status should still be in INIT.");
        }
    }

    /**
     * Validates that the issuance process is not skipped during a credential
     * management status transition.
     * <p>
     * Throws an {@link IllegalStateException} if an ISSUE event is requested while
     * the management object is not yet in
     * the ISSUED state. This ensures that the credential issuance process cannot be
     * bypassed and enforces correct state transitions.
     *
     * @param managementEvent the management event to process (must not be null)
     * @param mgmt            the credential management object to check (must not be
     *                        null)
     * @throws IllegalStateException if an ISSUE event is attempted before the
     *                               management object is in ISSUED state
     */
    private static void validateIssuanceNotSkipped(CredentialManagementEvent managementEvent,
            CredentialManagement mgmt) {
        if (managementEvent == CredentialManagementEvent.ISSUE && !mgmt.getCredentialManagementStatus().isIssued()) {
            throw new IllegalStateException("Issuance process may not be skipped");
        }
    }

    /**
     * Retrieve the current status of a credential offer.
     *
     * <p>
     * Loads the credential and returns a mapped {@link StatusResponseDto}. This
     * method is
     * transactional and not read-only because loading the credential may update its
     * state when
     * the offer has expired.
     * </p>
     *
     * @param credentialManagementId the id of the credential offer
     * @return the {@link StatusResponseDto} representing the credential's current
     *         status
     * @throws ResourceNotFoundException if no credential with the given id exists
     */
    @Transactional
    public StatusResponseDto getCredentialStatus(UUID credentialManagementId) {
        CredentialManagement credentialManagement = getCredentialManagementWithExpirationCheck(credentialManagementId);

        if (credentialManagement.isPreIssuanceProcess()) {
            var credentialOffer = credentialManagement.getCredentialOffers()
                    .stream()
                    .findFirst()
                    .orElseThrow(() -> new ResourceNotFoundException(
                            "No credential offer found for management id %s".formatted(credentialManagementId)));

            return toStatusResponseDto(credentialOffer);
        }

        return toStatusResponseDto(credentialManagement);
    }

    /**
     * Retrieve the current status of a specific credential offer.
     *
     * <p>
     * Loads the credential and returns a mapped {@link StatusResponseDto}. This
     * method is
     * transactional and not read-only because loading the credential may update its
     * state when
     * the offer has expired.
     * </p>
     *
     * @param credentialManagementId the id of the credential offer
     * @param offerId                the id of the offer
     * @return the {@link StatusResponseDto} representing the credential's current
     *         status
     * @throws ResourceNotFoundException if no credential with the given id exists
     */
    @Transactional
    public StatusResponseDto getCredentialOfferStatus(UUID credentialManagementId, UUID offerId) {
        CredentialOffer offer = getCredentialOfferWithExpirationCheck(offerId);
        if (!offer.getCredentialManagement().getId().equals(credentialManagementId)) {
            throw new ResourceNotFoundException("No offer with offerId %s found".formatted(offerId));
        }

        return toStatusResponseDto(offer);
    }

    /**
     * Create a credential offer and return its deeplink.
     *
     * <p>
     * Validates the provided request, determines the issuance batch size from
     * the issuer metadata, creates and persists a new credential offer and then
     * builds the deeplink representation for the created offer.
     * </p>
     *
     * @param request the create credential offer request
     * @return a {@link CredentialWithDeeplinkResponseDto} containing the created
     *         credential offer and its deeplink
     * @throws BadRequestException   if the request is invalid or referenced
     *                               resources cannot be resolved
     * @throws IllegalStateException if the credential configuration format is
     *                               unsupported
     */
    @Transactional
    public CredentialWithDeeplinkResponseDto createCredentialOfferAndGetDeeplink(
            @Valid CreateCredentialOfferRequestDto request) {

        var offerData = readOfferData(request.getCredentialSubjectData());
        validationService.validateCredentialOfferCreateRequest(request, offerData);

        var credentialMgmt = createCredentialOffer(request, offerData);
        var credentialOffer = credentialMgmt.getCredentialOffers().stream()
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No credential offer created"));

        return CredentialOfferMapper.toCredentialWithDeeplinkResponseDto(
                applicationProperties, credentialMgmt, credentialOffer);
    }

    /**
     * Creates an initial credential offer for renewal purposes.
     *
     * @param credentialManagement the credential management
     * @return the created credential offer
     */
    public CredentialOffer createInitialCredentialOfferForRenewal(CredentialManagement credentialManagement) {
        var offer = persistenceService.saveCredentialOffer(
                CredentialOffer.builder()
                        .nonce(UUID.randomUUID())
                        .credentialManagement(credentialManagement)
                        .credentialStatus(CredentialOfferStatusType.REQUESTED)
                        .build());

        credentialManagement.addCredentialOffer(offer);
        credentialManagement.setRenewalRequestCnt(credentialManagement.getRenewalRequestCnt() + 1);

        persistenceService.saveCredentialManagement(credentialManagement);

        return offer;
    }

    /**
     * Updates an existing {@link CredentialOffer} using data from a renewal
     * response.
     *
     * <p>
     * Constructs a temporary {@link CreateCredentialOfferRequestDto} from the
     * provided
     * {@code request}, validates the constructed request against issuer metadata
     * and claim
     * constraints, resolves the referenced status lists, applies the refreshed data
     * to
     * {@code existingOffer}, persists the updated offer and registers its status
     * list indexes.
     * </p>
     *
     * @param request       the renewal response containing new offer data (must be
     *                      valid)
     * @param existingOffer the persisted credential offer to update
     * @return the persisted {@link CredentialOffer} after applying the renewal data
     * @throws BadRequestException   if validation fails or referenced status lists
     *                               cannot be resolved
     * @throws IllegalStateException if the credential configuration format is
     *                               unsupported
     */
    public CredentialOffer updateOfferFromRenewalResponse(@Valid RenewalResponseDto request,
            CredentialOffer existingOffer) {

        CreateCredentialOfferRequestDto newOffer = CredentialOfferMapper.toOfferFromRenewal(request);
        var offerData = readOfferData(newOffer.getCredentialSubjectData());

        validationService.validateCredentialOfferCreateRequest(newOffer, offerData);

        var statusLists = statusListOrchestrator.resolveAndValidateStatusLists(newOffer);

        // Validate issuer DIDs match
        var issuerDid = validationService.determineIssuerDid(newOffer, applicationProperties.getIssuerId());
        validationService.ensureMatchingIssuerDids(issuerDid, applicationProperties.getIssuerId(), statusLists);

        CredentialOfferMapper.updateOfferFromDto(existingOffer, newOffer, offerData, applicationProperties);

        CredentialOffer entity = persistenceService.saveCredentialOffer(existingOffer);

        persistenceService.saveStatusListEntries(
                statusLists,
                entity.getId(),
                issuerMetadata.getIssuanceBatchSize());

        return entity;
    }

    /**
     * Update the offer data for a deferred credential.
     *
     * <p>
     * Loads the credential offer with a pessimistic write lock and verifies that
     * the
     * offer is a deferred offer currently in the {@code DEFERRED} state. If the
     * check
     * fails a {@link BadRequestException} is thrown. Further processing (validation
     * and
     * persisting the updated offer data) continues after this method's initial
     * checks.
     * </p>
     *
     * @param credentialManagementId the id of the credential management offer to
     *                               update
     * @param offerDataMap           the credential subject data to apply to the
     *                               deferred offer
     * @return an {@link UpdateStatusResponseDto} describing the updated credential
     *         status
     * @throws ResourceNotFoundException if no credential offer with the given id
     *                                   exists
     * @throws BadRequestException       if the credential is not deferred or has an
     *                                   incorrect status
     */
    @Transactional
    public UpdateStatusResponseDto updateOfferDataForDeferred(@NotNull UUID credentialManagementId,
            Map<String, Object> offerDataMap) {
        var mgmt = getCredentialManagementWithExpirationCheck(credentialManagementId);
        var storedCredentialOffer = mgmt.getCredentialOffers().stream()
                .filter(CredentialOffer::isDeferredOffer)
                .findFirst()
                .orElseThrow(() -> new BadRequestException(
                        "Credential is either not deferred or has an incorrect status, cannot update offer data"));

        if (!storedCredentialOffer.isDeferredOffer()
                || storedCredentialOffer.getCredentialStatus() != CredentialOfferStatusType.DEFERRED) {
            throw new BadRequestException(
                    "Credential is either not deferred or has an incorrect status, cannot update offer data");
        }

        // check if offerData matches the expected metadata claims
        var offerData = readOfferData(offerDataMap);
        var credentialOfferMetadata = storedCredentialOffer.getMetadataCredentialSupportedId().getFirst();
        var credentialConfig = issuerMetadata.getCredentialConfigurationById(credentialOfferMetadata);

        validationService.validateCredentialRequestOfferData(offerData, true, credentialConfig);

        // update the offer data
        stateService.markOfferAsReady(storedCredentialOffer);
        storedCredentialOffer.setOfferData(offerData);
        persistenceService.saveCredentialOffer(storedCredentialOffer);

        return toUpdateStatusResponseDto(storedCredentialOffer);
    }

    /**
     * Retrieve the {@link ConfigurationOverride} for a credential offer identified
     * by the given tenant id.
     *
     * @param tenantId the tenant id associated with the credential offer
     * @return the {@link ConfigurationOverride} of the found credential offer, or
     *         {@code null} if no override is set
     * @throws ResourceNotFoundException if no credential offer exists for the
     *                                   provided tenant id
     */
    @Transactional
    public ConfigurationOverride getConfigurationOverrideByTenantId(UUID tenantId) {
        var offer = persistenceService.findCredentialOfferByMetadataTenantId(tenantId);
        return offer.getConfigurationOverride();
    }

    @Transactional
    public CredentialOffer getCredentialOfferByTenantId(UUID tenantId) {
        var offer = persistenceService.findCredentialOfferByMetadataTenantId(tenantId);
        return offer;
    }

    /**
     * Retrieves credential management and checks for expiration, expiring the
     * affected offers.
     *
     * @param managementId the management ID
     * @return the credential management with updated offer states
     */
    private CredentialManagement getCredentialManagementWithExpirationCheck(UUID managementId) {
        var mgmt = persistenceService.findCredentialManagementById(managementId);

        mgmt.getCredentialOffers().forEach(offer -> {
            // Make sure only offer is returned if it is not expired
            if (CredentialOfferStatusType.getExpirableStates().contains(offer.getCredentialStatus())
                    && offer.hasExpirationTimeStampPassed()) {
                expireCredentialOffer(offer);
            }
        });

        return persistenceService.saveCredentialManagement(mgmt);
    }

    private CredentialOffer getCredentialOfferWithExpirationCheck(UUID offerId) {
        var offer = persistenceService.findCredentialOfferByIdForUpdate(offerId);

        if (CredentialOfferStatusType.getExpirableStates()
                .contains(
                        offer.getCredentialStatus())
                && offer.hasExpirationTimeStampPassed()) {
            expireCredentialOffer(offer);
        }

        return offer;
    }

    /**
     * Creates and persists a new credential offer.
     *
     * @param requestDto the credential offer request
     * @param offerData  the parsed offer data
     * @return the created credential management with the offer
     */
    private CredentialManagement createCredentialOffer(
            CreateCredentialOfferRequestDto requestDto,
            Map<String, Object> offerData) {

        long offerDuration = requestDto.getOfferValiditySeconds() > 0
                ? requestDto.getOfferValiditySeconds()
                : applicationProperties.getOfferValidity();

        var expiration = Instant.now().plusSeconds(
                offerDuration);

        // Get used status lists and ensure they are managed by the issuer
        var statusLists = statusListOrchestrator.resolveAndValidateStatusLists(requestDto);

        // Validate issuer DIDs match
        var issuerDid = validationService.determineIssuerDid(requestDto, applicationProperties.getIssuerId());
        validationService.ensureMatchingIssuerDids(issuerDid, applicationProperties.getIssuerId(), statusLists);

        CredentialManagement credentialManagement = persistenceService.saveCredentialManagement(
                CredentialManagement.builder()
                        .id(UUID.randomUUID())
                        .accessToken(UUID.randomUUID())
                        .credentialManagementStatus(CredentialStatusManagementType.INIT)
                        .renewalResponseCnt(0)
                        .renewalRequestCnt(0)
                        .metadataTenantId(applicationProperties.isSignedMetadataEnabled() ? UUID.randomUUID() : null)
                        .build());

        CredentialOffer entity = persistenceService.saveCredentialOffer(
                CredentialOffer.builder()
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
                        .credentialManagement(credentialManagement)
                        .build());

        credentialManagement.addCredentialOffer(entity);
        var newCredentialManagement = persistenceService.saveCredentialManagement(credentialManagement);

        log.debug("Created Credential offer {} valid until {}", entity.getId(), expiration.toEpochMilli());

        var statusListEntries = issuerMetadata.isBatchIssuanceAllowed() ? issuerMetadata.getIssuanceBatchSize() : 1;

        persistenceService.saveStatusListEntries(
                statusLists,
                entity.getId(),
                statusListEntries);

        return newCredentialManagement;
    }

    /**
     * Expires a credential offer by updating its state and publishing an event.
     *
     * @param credential the credential offer to expire
     * @return the updated credential offer
     * @throws BadRequestException if the credential is already in a terminal state
     */
    private CredentialOffer expireCredentialOffer(CredentialOffer credential) {
        var currentStatus = credential.getCredentialStatus();

        if (credential.getCredentialStatus().isTerminalState()) {
            throw new BadRequestException(
                    String.format(STATUS_NOT_CHANGEABLE, CredentialOfferStatusType.EXPIRED, currentStatus));
        }

        stateService.expireOfferAndPublish(credential);

        return credential;
    }
}