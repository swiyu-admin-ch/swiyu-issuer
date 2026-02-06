package ch.admin.bj.swiyu.issuer.service.offer;

import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.DataIntegrityService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SDJWT_PROTECTED_CLAIMS;

/**
 * Service responsible for validating credential offers and their data.
 *
 * <p>This service encapsulates all validation logic related to credential offers,
 * including format validation, claim validation, date validation, and issuer DID matching.</p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialOfferValidationService {

    private final IssuerMetadata issuerMetadata;
    private final DataIntegrityService dataIntegrityService;

    /**
     * Validates a credential offer create request, performing sanity checks with configurations.
     *
     * @param createCredentialRequest the create credential request to be validated
     * @param offerData the parsed offer data
     * @throws BadRequestException if validation fails
     * @throws IllegalStateException if the credential configuration format is unsupported
     */
    public void validateCredentialOfferCreateRequest(
            @Valid CreateCredentialOfferRequestDto createCredentialRequest,
            Map<String, Object> offerData) {

        var credentialOfferMetadataId = createCredentialRequest.getMetadataCredentialSupportedId().getFirst();

        // Date checks, if exists
        validateOfferedCredentialValiditySpan(createCredentialRequest);

        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(credentialOfferMetadataId);

        // Check if credential format is supported otherwise throw error
        validateCredentialFormat(credentialConfiguration);

        var metadata = createCredentialRequest.getCredentialMetadata();
        var isDeferredRequest = (metadata != null && Boolean.TRUE.equals(metadata.deferred()));

        validateCredentialRequestOfferData(offerData, isDeferredRequest, credentialConfiguration);
    }

    /**
     * Validates the credential format is supported.
     *
     * @param credentialConfiguration the credential configuration
     * @throws IllegalStateException if the format is not supported
     */
    public void validateCredentialFormat(CredentialConfiguration credentialConfiguration) {
        if (!List.of("vc+sd-jwt", "dc+sd-jwt").contains(credentialConfiguration.getFormat())) {
            throw new IllegalStateException("Unsupported credential configuration format %s, only supporting dc+sd-jwt"
                    .formatted(credentialConfiguration.getFormat()));
        }
    }

    /**
     * Validates the credential request offer data.
     *
     * @param offerData the offer data to validate
     * @param isDeferredRequest whether this is a deferred request
     * @param credentialConfiguration the credential configuration
     * @throws BadRequestException if validation fails
     */
    public void validateCredentialRequestOfferData(
            Map<String, Object> offerData,
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
        validateProtectedClaims(validatedOfferData);

        var metadataClaims = Optional.ofNullable(credentialConfiguration.getClaims())
                .orElseGet(HashMap::new)
                .keySet();

        validateClaimsMissing(metadataClaims, validatedOfferData, credentialConfiguration);
        validateClaimsSurplus(metadataClaims, validatedOfferData);
    }

    /**
     * Validates that offer data does not contain protected claims.
     *
     * @param offerData the offer data to validate
     * @throws BadRequestException if protected claims are found
     */
    private void validateProtectedClaims(Map<String, Object> offerData) {
        List<String> reservedClaims = new ArrayList<>(offerData.keySet().stream()
                .filter(SDJWT_PROTECTED_CLAIMS::contains)
                .toList());

        if (!reservedClaims.isEmpty()) {
            throw new BadRequestException(
                    "The following claims are not allowed in the credentialSubjectData: " + reservedClaims);
        }
    }

    /**
     * Checks if all claims published as mandatory in the metadata are present in the offer.
     *
     * @param metadataClaims the expected metadata claims
     * @param offerData the offer data
     * @param credentialConfiguration the credential configuration
     * @throws BadRequestException if mandatory claims are missing
     */
    private void validateClaimsMissing(
            Set<String> metadataClaims,
            Map<String, Object> offerData,
            CredentialConfiguration credentialConfiguration) {

        var missingOfferedClaims = new HashSet<>(metadataClaims);
        missingOfferedClaims.removeAll(offerData.keySet());
        // Remove optional claims
        missingOfferedClaims.removeIf(claimKey ->
                !credentialConfiguration.getClaims().get(claimKey).isMandatory());

        if (!missingOfferedClaims.isEmpty()) {
            throw new BadRequestException(
                    "Mandatory credential claims are missing! %s"
                            .formatted(String.join(",", missingOfferedClaims)));
        }
    }

    /**
     * Checks the offerData for claims not expected in the metadata.
     *
     * @param metadataClaims the expected metadata claims
     * @param offerData the offer data
     * @throws BadRequestException if unexpected claims are found
     */
    private void validateClaimsSurplus(Set<String> metadataClaims, Map<String, Object> offerData) {
        var surplusOfferedClaims = new HashSet<>(offerData.keySet());
        surplusOfferedClaims.removeAll(metadataClaims);

        if (!surplusOfferedClaims.isEmpty()) {
            throw new BadRequestException(
                    "Unexpected credential claims found! %s"
                            .formatted(String.join(",", surplusOfferedClaims)));
        }
    }

    /**
     * Validates the validity span of the offered credential.
     *
     * @param credentialOffer the credential offer to validate
     * @throws BadRequestException if the validity span is invalid
     */
    public void validateOfferedCredentialValiditySpan(@Valid CreateCredentialOfferRequestDto credentialOffer) {
        var validUntil = credentialOffer.getCredentialValidUntil();
        if (validUntil == null) {
            return;
        }
        if (validUntil.isBefore(Instant.now())) {
            throw new BadRequestException(
                    "Credential is already expired (would only be valid until %s, server time is %s)"
                            .formatted(validUntil, Instant.now()));
        }
        var validFrom = credentialOffer.getCredentialValidFrom();
        if (validFrom != null && validFrom.isAfter(validUntil)) {
            throw new BadRequestException(
                    "Credential would never be valid - Valid from %s until %s"
                            .formatted(validFrom, validUntil));
        }
    }

    /**
     * The issuer did (iss) of VCs and the linked status lists have to be the same or verifications will fail.
     * <p>
     * Developer Note: Since Token Status List Draft 04 requirement for matching iss claim in Referenced Token
     * and Status List Token has been removed. The wallet and verifier must be first migrated before this check
     * can be removed.
     *
     * @param issuerDid the issuer DID
     * @param defaultIssuerId the default issuer ID
     * @param statusLists the status lists to validate
     * @throws BadRequestException if issuer DIDs don't match
     */
    @Deprecated(since = "Token Status List Draft 04")
    public void ensureMatchingIssuerDids(
            String issuerDid,
            String defaultIssuerId,
            List<StatusList> statusLists) {

        var mismatchingStatusLists = statusLists.stream()
                .filter(statusList -> !determineIssuerDid(statusList, defaultIssuerId).equals(issuerDid))
                .toList();

        if (!mismatchingStatusLists.isEmpty()) {
            throw new BadRequestException(
                    "Status List issuer did is not the same as credential issuer did for %s"
                            .formatted(mismatchingStatusLists.stream()
                                    .map(StatusList::getUri)
                                    .toList()
                                    .toString()));
        }
    }

    /**
     * Determines the issuer DID for a given status list.
     * <p>
     * If the status list contains a configuration override with a non-empty issuer DID,
     * that value is returned. Otherwise, the provided default issuer ID is used.
     *
     * @param statusList the status list to resolve the issuer DID from
     * @param defaultIssuerId the default issuer ID to use if no override is present
     * @return the resolved issuer DID
     */
    private static String determineIssuerDid(StatusList statusList, String defaultIssuerId) {
        var override = statusList.getConfigurationOverride();
        if (override != null && StringUtils.isNotEmpty(override.issuerDid())) {
            return override.issuerDid();
        }
        return defaultIssuerId;
    }

    /**
     * Determines the issuer DID from the request or default configuration.
     *
     * @param requestDto the credential offer request
     * @param defaultIssuerId the default issuer ID
     * @return the issuer DID to use
     */
    public String determineIssuerDid(CreateCredentialOfferRequestDto requestDto, String defaultIssuerId) {
        var override = requestDto.getConfigurationOverride();
        if (override != null && StringUtils.isNotEmpty(override.issuerDid())) {
            return override.issuerDid();
        }

        return defaultIssuerId;
    }
}

