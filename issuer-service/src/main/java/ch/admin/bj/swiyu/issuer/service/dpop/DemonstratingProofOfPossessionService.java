package ch.admin.bj.swiyu.issuer.service.dpop;

import java.text.ParseException;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionError;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.issuer.service.MetadataService;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.credential.KeyAttestationService;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;

/**
 * Provide functionality to embed Demonstrating Proof of Possession (DPoP) functionality in the greater application
 * See <a href="https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid">RFC9449</a>
 * More summarized for users of DPoP in
 * <a href="https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/dpop-tokens.html">spring-security documentation</a>
 */
@Service
@RequiredArgsConstructor
public class DemonstratingProofOfPossessionService {


    protected static final String DPOP_KEY_ATTESTATION_CLAIM = "key_attestation";
    private final ApplicationProperties applicationProperties;
    private final NonceService nonceService;
    private final OAuthService oAuthService;
    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialManagementRepository credentialManagementRepository;
    private final DemonstratingProofOfPossessionValidationService demonstratingProofOfPossessionValidationService;
    private final MetadataService metadataService;
    private final KeyAttestationService keyAttestationService;


    /**
     * Add a self-contained nonce to be used in Demonstrating Proof of Possession JWTs
     *
     * @param headers the header to be extended with a DPoP-Nonce header
     */
    public void addDpopNonce(HttpHeaders headers) {
        headers.set("DPoP-Nonce", nonceService.createNonce().nonce());
    }

    /**
     * Validate the Demonstrating Proof of Possession for the initial call of the token endpoint and register the public key provided therein
     *
     * @param preAuthCode One time Pre-Auth code used for the token_endpoint request
     * @param dpop        Serialized Json Web Token to be validated, must contain nonce and jwk with the public key of the holder
     * @param request     HTTP request associated with the DPoP for validating Request Method and URI
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void registerDpop(@NotBlank String preAuthCode, @Nullable String dpop, HttpRequest request) {
        if (canSkipDpopValidation(dpop, false)) {
            return;
        }
        var dpopJwt = demonstratingProofOfPossessionValidationService.parseDpopJwt(dpop, request);
        var credentialOffer = credentialOfferRepository.findByPreAuthorizedCode(UUID.fromString(preAuthCode)).orElseThrow();
        var mgmt = credentialOffer.getCredentialManagement();
        if (requiresKeyAttestationIso18045High(credentialOffer)) {
            validateDPoPKeyAttestation(dpopJwt);
        }
        mgmt.setDPoPKey(dpopJwt.getHeader().getJWK().toJSONObject());
        credentialManagementRepository.save(mgmt);
    }

    /**
     * Validates the DPoP with the registered public key which is associated with the provided access token
     *
     * @param accessToken OAuth2.0 Access Token, given as BEARER token
     * @param dpop        Serialized Json Web Token to be validated, must contain nonce and ath
     * @param request     HTTP request associated with the DPoP for validating Request Method and URI
     */
    @Transactional
    public void validateDpop(@NotBlank String accessToken, @Nullable String dpop, @NotNull HttpRequest request) {
        var credentialManagement = oAuthService.getCredentialManagementByAccessToken(accessToken);
        if (canSkipDpopValidation(dpop, credentialManagement.hasDPoPKey())) {
            return;
        }
        var dpopJwt = demonstratingProofOfPossessionValidationService.parseDpopJwt(dpop, request);
        demonstratingProofOfPossessionValidationService.validateAccessTokenBinding(accessToken, dpopJwt, credentialManagement.getDpopKey());
    }

    /**
     * Used to refresh the DPoP binding for more details see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-5">DPoP Access Token Request</a>
     * <br>
     * When an authorization server supporting DPoP issues a refresh token to a public client that presents a valid DPoP proof at the token endpoint,
     * <em>the refresh token MUST be bound to the respective public key</em>. The binding MUST be validated when the refresh token is later presented to get new access tokens.
     * As a result, such a client MUST present a DPoP proof for the same key that was used to obtain the refresh token each time that refresh token is used to obtain
     * a new access token.
     *
     * @param refreshToken OAuth2.0 refresh_token
     * @param dpop         dpop for validating key binding
     * @param request      http request with which the dpop was received for validating uri & method
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void refreshDpop(String refreshToken, String dpop, ServletServerHttpRequest request) {
        var credentialManagement = oAuthService.getUnrevokedCredentialOfferByRefreshToken(refreshToken);
        if (canSkipDpopValidation(dpop, credentialManagement.hasDPoPKey())) {
            return;
        }
        var dpopJwt = demonstratingProofOfPossessionValidationService.parseDpopJwt(dpop, request);
        demonstratingProofOfPossessionValidationService.validateBoundPublicKey(dpopJwt, credentialManagement.getDpopKey());
    }


    /**
     * Checks if the dpop has not been included and is set to be optional.
     */
    private boolean canSkipDpopValidation(@Nullable String dpop, boolean hasRegisteredDPoPKey) {
        if (StringUtils.isBlank(dpop)) {
            // No DPoP Header was provided in the credential request
            if (applicationProperties.isDpopEnforce() || hasRegisteredDPoPKey) {
                // A DPoP Header was strictly required ==> Aborting with exception
                throw new DemonstratingProofOfPossessionException("Authorization server requires nonce in DPoP proof",
                        DemonstratingProofOfPossessionError.USE_DPOP_NONCE);
            } else {
                // Not enforced, so not having a dpop is fine
                return true;
            }
        }
        // DPoP header is present -> DPoP Validation must be performed
        return false;
    }

    /**
     * Load the Issuer Metadata to evaluate if any the credentials offered require iso_18045_high AttackPotentialResistance
     * @param credentialOffer the offer to be evaluated
     * @return true if a key attestation with iso_18045_high is required, else false
     */
    protected boolean requiresKeyAttestationIso18045High(CredentialOffer credentialOffer) {
        var metadata = metadataService.getUnsignedIssuerMetadata();
        var offeredCredentialTypes = credentialOffer.getMetadataCredentialSupportedId();
        if (offeredCredentialTypes == null) {
            // The credential offer has no information on what credentials will be offered.
            // This is the case should authorized code flow be used instead of pre-authorized code flow
            // The type of dpop binding is up to the wallet
            return false;
        }
        return credentialOffer.getMetadataCredentialSupportedId().stream()
            .flatMap(offerCredentialSupportedId -> metadata.getCredentialConfigurationById(offerCredentialSupportedId)
                .getProofTypesSupported().values().stream())
            .map(SupportedProofType::getKeyAttestationRequirement)
            .filter(Objects::nonNull) // Key Attestation Requirement can be null
            .flatMap(keyAttestationRequirement -> keyAttestationRequirement.getKeyStorage().stream())
            .anyMatch(attackPotentialResistanceRequirement -> AttackPotentialResistance.ISO_18045_HIGH.equals(attackPotentialResistanceRequirement));
    }

    /**
     * Validates the DPoP key attestation contained in the provided DPoP as {@link SignedJWT}.
     *
     * @param dpopJwt the DPoP {@code SignedJWT} that must contain a {@code key_attestation}
     *                claim
     * @throws DemonstratingProofOfPossessionException if the {@code key_attestation}
     *         claim is missing, blank, or cannot be parsed as a valid attestation JWT
     */
    protected void validateDPoPKeyAttestation(SignedJWT dpopJwt) {
        /**
         * A Key Attestation JWT in base64 serialized form
         */
        Object dpopKeyAttestation = dpopJwt.getHeader().getCustomParam(DPOP_KEY_ATTESTATION_CLAIM);
        if (Objects.isNull(dpopKeyAttestation)) {
            throw new DemonstratingProofOfPossessionException("Missing DPoP Key Attestation",
                    DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
        keyAttestationService.validateKeyAttestation(
                KeyAttestationRequirement.builder()
                        .keyStorage(List.of(AttackPotentialResistance.ISO_18045_HIGH)).build(),
                dpopKeyAttestation.toString());
    }

}