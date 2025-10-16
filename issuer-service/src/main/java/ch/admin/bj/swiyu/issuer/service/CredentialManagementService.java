package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.*;
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
import ch.admin.bj.swiyu.issuer.service.webhook.StateChangeEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
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

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer.readOfferData;
import static ch.admin.bj.swiyu.issuer.service.CredentialOfferMapper.*;
import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SDJWT_PROTECTED_CLAIMS;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.StatusResponseMapper.toStatusResponseDto;

@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialManagementService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final ObjectMapper objectMapper;
    private final StatusListService statusListService;
    private final IssuerMetadata issuerMetadata;
    private final ApplicationProperties applicationProperties;
    private final DataIntegrityService dataIntegrityService;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final AvailableStatusListIndexRepository availableStatusListIndexRepository;
    private final Random random = new Random();

    @Transactional // not readonly since expired credentails gets updated here automatically
    public CredentialInfoResponseDto getCredentialOfferInformation(UUID credentialId) {
        var credential = this.getCredential(credentialId);
        var deeplink = getOfferDeeplinkFromCredential(credential);

        return toCredentialInfoResponseDto(credential, deeplink);
    }

    @Transactional // not readonly since expired credentails gets updated here automatically
    public String getCredentialOfferDeeplink(UUID credentialId) {
        var credential = this.getCredential(credentialId);
        return this.getOfferDeeplinkFromCredential(credential);

    }

    @Transactional
    public UpdateStatusResponseDto updateCredentialStatus(@NotNull UUID credentialId,
                                                          @NotNull UpdateCredentialStatusRequestTypeDto requestedNewStatus) {
        var credentialOfferForUpdate = getCredentialForUpdate(credentialId);
        var newStatus = toCredentialStatusType(requestedNewStatus);
        var credential = updateCredentialStatus(credentialOfferForUpdate, newStatus);

        return toUpdateStatusResponseDto(credential);
    }

    @Transactional // not readonly since expired credentials gets updated here automatically
    public StatusResponseDto getCredentialStatus(UUID credentialId) {
        CredentialOffer credential = this.getCredential(credentialId);
        return toStatusResponseDto(credential);
    }

    @Transactional
    public CredentialWithDeeplinkResponseDto createCredentialOfferAndGetDeeplink(@Valid CreateCredentialRequestDto request) {
        validateCredentialOfferCreateRequest(request);
        var credential = this.createCredentialOffer(request, issuerMetadata.getIssuanceBatchSize());
        var offerLinkString = this.getOfferDeeplinkFromCredential(credential);
        return CredentialOfferMapper.toCredentialWithDeeplinkResponseDto(credential, offerLinkString);
    }

    /**
     * Set the state of all expired credential offers to expired and delete the
     * person data associated with it.
     */
    @Scheduled(initialDelay = 0, fixedDelayString = "${application.offer-expiration-interval}")
    @SchedulerLock(name = "expireOffers")
    @Transactional
    public void expireOffers() {
        var expireStates = CredentialStatusType.getExpirableStates();
        var expireTimeStamp = Instant.now().getEpochSecond();
        log.info("Expiring {} offers", credentialOfferRepository
                .countByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp));
        var expiredOffers = credentialOfferRepository
                .findByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp);
        expiredOffers.forEach(offer -> updateCredentialStatus(offer, CredentialStatusType.EXPIRED));
    }

    public void validateOfferData(Map<String, Object> offerData) {
        var validatedOfferData = dataIntegrityService.getVerifiedOfferData(offerData, null);

        // check if credentialSubjectData contains protected claims
        List<String> duplicates = new ArrayList<>(validatedOfferData.keySet().stream()
                .filter(SDJWT_PROTECTED_CLAIMS::contains)
                .toList());

        if (!duplicates.isEmpty()) {
            throw new BadRequestException(
                    "The following claims are not allowed in the credentialSubjectData: " + duplicates);
        }
    }

    @Transactional
    public UpdateStatusResponseDto updateOfferDataForDeferred(@NotNull UUID credentialId, Map<String, Object> offerDataMap) {
        var storedCredentialOffer = getCredentialForUpdate(credentialId);

        // Check if is deferred credential and in deferred state
        if (!storedCredentialOffer.isDeferredOffer()
                && storedCredentialOffer.getCredentialStatus() == CredentialStatusType.DEFERRED) {
            throw new BadRequestException(
                    "Credential is either not deferred or has an incorrect status, cannot update offer data");
        }

        // check if offerData matches the expected metadata claims
        var offerData = readOfferData(offerDataMap);
        validateOfferData(offerData);

        // update the offer data
        storedCredentialOffer.markAsReadyForIssuance(offerData);
        credentialOfferRepository.save(storedCredentialOffer);

        return toUpdateStatusResponseDto(storedCredentialOffer);
    }

    /**
     * Returns the credential offer for the given id.
     * <p>
     * Attention: If it is expired it will update its state before returning it.
     */
    private CredentialOffer getCredential(UUID credentialId) {

        // Check if optional can be default
        return this.credentialOfferRepository.findById(credentialId)
                .map(offer -> {
                    // Make sure only offer is returned if it is not expired
                    if (CredentialStatusType.getExpirableStates().contains(offer.getCredentialStatus())
                            && offer.hasExpirationTimeStampPassed()) {
                        return updateCredentialStatus(getCredentialForUpdate(offer.getId()),
                                CredentialStatusType.EXPIRED);
                    }
                    return offer;
                })
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }

    /**
     * Validates a credential offer create request, doing sanity checks with
     * configurations
     *
     * @param createCredentialRequest the create credential request to be validated
     * @return the credential configuration used by the credential offer
     */
    private void validateCredentialOfferCreateRequest(@Valid CreateCredentialRequestDto createCredentialRequest) {
        var credentialOfferMetadata = createCredentialRequest.getMetadataCredentialSupportedId().getFirst();
        if (!issuerMetadata.getCredentialConfigurationSupported().containsKey(credentialOfferMetadata)) {
            throw new BadRequestException("Credential offer metadata %s is not supported - should be one of %s"
                    .formatted(credentialOfferMetadata,
                            String.join(", ", issuerMetadata.getCredentialConfigurationSupported().keySet())));
        }
        // Date checks, if exists
        validateOfferedCredentialValiditySpan(createCredentialRequest);
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(credentialOfferMetadata);

        var metadataClaims = Optional.ofNullable(credentialConfiguration.getClaims()).orElseGet(HashMap::new).keySet();
        if (List.of("vc+sd-jwt", "dc+sd-jwt").contains(credentialConfiguration.getFormat())) {
            var offerData = dataIntegrityService.getVerifiedOfferData(readOfferData(createCredentialRequest.getCredentialSubjectData()),
                    null);

            if (CollectionUtils.isEmpty(offerData)
                    && (createCredentialRequest.getCredentialMetadata() == null
                    || Boolean.FALSE.equals(createCredentialRequest.getCredentialMetadata().deferred()))) {
                throw new BadRequestException("Credential claims (credential subject data) is missing!");
            }

            validateClaimsMissing(metadataClaims, offerData, credentialConfiguration);
            validateClaimsSurplus(metadataClaims, offerData);
        } else {
            throw new IllegalStateException("Unsupported credential configuration format %s, only supporting dc+sd-jwt"
                    .formatted(credentialConfiguration.getFormat()));
        }
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

    private void validateOfferedCredentialValiditySpan(@Valid CreateCredentialRequestDto credentialOffer) {
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

    private String getOfferDeeplinkFromCredential(CredentialOffer credential) {

        var grants = new GrantsDto(new PreAuthorizedCodeGrantDto(credential.getPreAuthorizedCode()));

        var credentialOffer = CredentialOfferDto.builder()
                .credentialIssuer(applicationProperties.getExternalUrl())
                .credentials(credential.getMetadataCredentialSupportedId())
                .grants(grants)
                .version(applicationProperties.getRequestOfferVersion())
                .build();

        String credentialOfferString;
        try {
            credentialOfferString = URLEncoder.encode(objectMapper.writeValueAsString(credentialOffer),
                    Charset.defaultCharset());
        } catch (JsonProcessingException e) {
            throw new JsonException(
                    "Error processing credential offer for credential with id %s".formatted(credential.getId()), e);
        }

        return String.format("%s://?credential_offer=%s", applicationProperties.getDeeplinkSchema(),
                credentialOfferString);
    }

    private CredentialOffer createCredentialOffer(CreateCredentialRequestDto requestDto, int issuanceBatchSize) {
        var expiration = Instant.now().plusSeconds(requestDto.getOfferValiditySeconds() > 0
                ? requestDto.getOfferValiditySeconds()
                : applicationProperties.getOfferValidity());
        // Check if credentialSubjectData contains protected claims
        var offerData = readOfferData(requestDto.getCredentialSubjectData());
        validateOfferData(offerData);

        // Get used status lists and ensure they are managed by the issuer
        var statusListUris = requestDto.getStatusLists();
        var statusLists = statusListService.findByUriIn(statusListUris);
        if (statusLists.size() != requestDto.getStatusLists().size()) {
            throw new BadRequestException(String.format("Could not resolve all provided status lists, only found %s",
                    statusLists.stream().map(StatusList::getUri).collect(Collectors.joining(", "))));
        }
        ensureMatchingIssuerDids(requestDto, statusLists);


        var entity = CredentialOffer.builder()
                .credentialStatus(CredentialStatusType.OFFERED)
                .metadataCredentialSupportedId(requestDto.getMetadataCredentialSupportedId())
                .offerData(offerData)
                .offerExpirationTimestamp(expiration.getEpochSecond())
                .nonce(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialValidFrom(requestDto.getCredentialValidFrom())
                .deferredOfferValiditySeconds(requestDto.getDeferredOfferValiditySeconds())
                .credentialValidUntil(requestDto.getCredentialValidUntil())
                .credentialMetadata(toCredentialOfferMetadataDto(requestDto.getCredentialMetadata()))
                .configurationOverride(toConfigurationOverride(requestDto.getConfigurationOverride()))
                .build();
        entity = this.credentialOfferRepository.save(entity);
        log.debug("Created Credential offer {} valid until {}", entity.getId(), expiration.toEpochMilli());


        for (StatusList statusList : statusLists) {
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

            // Create Status List entries
            final var offerId = entity.getId();
            var offerStatuses = sampledNumbers.stream().map(freeIndex -> {
                var offerStatusKey = CredentialOfferStatusKey.builder()
                        .offerId(offerId)
                        .statusListId(statusList.getId())
                        .index(freeIndex)
                        .build();
                log.debug("Credential offer {} uses status list {} indexes {}", offerId, statusList.getUri(),
                        freeIndex);
                return CredentialOfferStatus.builder()
                        .id(offerStatusKey)
                        .build();
            }).toList();
            credentialOfferStatusRepository.saveAll(offerStatuses);
        }
        return entity;
    }


    /**
     * The issuer did (iss) of VCs and the linked status lists have to be the same or verifications will fail.
     * <p>
     * Developer Note: Since Token Status List Draft 04 requirement for matching iss claim in Referenced Token and Status List Token has been removed
     * The wallet and verifier must be first migrated before this check can be removed
     */
    @Deprecated(since = "Token Status List Draft 04")
    private void ensureMatchingIssuerDids(CreateCredentialRequestDto requestDto, List<StatusList> statusLists) {
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

    /**
     * @param credential the pessimistic write locked credential offer
     * @param newStatus  the new status assigned
     * @return the updated CredentialOffer
     */
    private CredentialOffer updateCredentialStatus(@NotNull CredentialOffer credential,
                                                   @NotNull CredentialStatusType newStatus) {

        var currentStatus = credential.getCredentialStatus();

        // Ignore no status changes and return. This needs to be checked first to
        // prevent unnecessary errors
        if (currentStatus == newStatus) {
            return credential;
        }

        // status is already in a terminal state and cannot be changed
        if (currentStatus.isTerminalState()) {
            throw new BadRequestException(
                    String.format("Tried to set %s but status is already %s", newStatus, currentStatus));
        }

        if (newStatus == CredentialStatusType.EXPIRED) {
            credential.expire();
        } else if (currentStatus.isProcessable()) {
            handlePreIssuanceStatusChange(credential, currentStatus, newStatus);
        } else {
            handlePostIssuanceStatusChange(credential, newStatus);
        }

        log.debug("Updating credential {} from {} to {}", credential.getId(), currentStatus, newStatus);
        var updatedCredentialOffer = this.credentialOfferRepository.save(credential);
        produceStateChangeEvent(updatedCredentialOffer.getId(), updatedCredentialOffer.getCredentialStatus());

        return updatedCredentialOffer;
    }

    private CredentialOffer getCredentialForUpdate(UUID credentialId) {
        return this.credentialOfferRepository.findByIdForUpdate(credentialId)
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Credential %s not found", credentialId)));
    }


    /**
     * Handles status changes before issuance (status cancelled, ready and expired)
     */
    private void handlePreIssuanceStatusChange(CredentialOffer credential,
                                               CredentialStatusType currentStatus,
                                               CredentialStatusType newStatus) {

        // if the new status is READY, then we can only set it if the old status was
        // deferred
        if (currentStatus == CredentialStatusType.DEFERRED && newStatus == CredentialStatusType.READY) {
            credential.changeStatus(CredentialStatusType.READY);
            return;
        }

        if (newStatus == CredentialStatusType.CANCELLED || newStatus == CredentialStatusType.REVOKED) {
            credential.cancel();
            return;
        }

        throw new BadRequestException(String.format(
                "Illegal state transition - Status cannot be updated from %s to %s", currentStatus, newStatus));
    }

    /**
     * Handles status changes after issuance (status suspended, revoked and issued)
     */
    private void handlePostIssuanceStatusChange(CredentialOffer credential, CredentialStatusType newStatus) {

        final Set<CredentialOfferStatus> offerStatusSet = credentialOfferStatusRepository
                .findByOfferId(credential.getId());

        if (offerStatusSet.isEmpty()) {
            throw new BadRequestException(
                    "No associated status lists found. Can not set a status to an already issued credential");
        }

        switch (newStatus) {
            case REVOKED -> statusListService.revoke(offerStatusSet);
            case SUSPENDED -> statusListService.suspend(offerStatusSet);
            case ISSUED -> statusListService.revalidate(offerStatusSet);
            default -> throw new BadRequestException(String.format(
                    "Illegal state transition - Status cannot be updated from %s to %s",
                    credential.getCredentialStatus(), newStatus));
        }

        credential.changeStatus(newStatus);
    }

    private void produceStateChangeEvent(UUID credentialOfferId, CredentialStatusType state) {
        var stateChangeEvent = new StateChangeEvent(
                credentialOfferId,
                state
        );
        applicationEventPublisher.publishEvent(stateChangeEvent);
    }
}