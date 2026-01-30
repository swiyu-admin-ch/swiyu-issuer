package ch.admin.bj.swiyu.issuer.service.dpop;

import ch.admin.bj.swiyu.issuer.dto.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionError;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Provide functionality to embed Demonstrating Proof of Possession (DPoP) functionality in the greater application
 * See <a href="https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid">RFC9449</a>
 * More summarized for users of DPoP in
 * <a href="https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/dpop-tokens.html">spring-security documentation</a>
 */
@Service
@RequiredArgsConstructor
public class DemonstratingProofOfPossessionService {


    private final ApplicationProperties applicationProperties;
    private final NonceService nonceService;
    private final OAuthService oAuthService;
    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialManagementRepository credentialManagementRepository;
    private final DemonstratingProofOfPossessionValidationService demonstratingProofOfPossessionValidationService;


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
    @Transactional
    public void registerDpop(@NotBlank String preAuthCode, @Nullable String dpop, HttpRequest request) {
        if (isDpopUnused(dpop)) {
            return;
        }
        var dpopJwt = demonstratingProofOfPossessionValidationService.parseDpopJwt(dpop, request);
        var credentialOffer = credentialOfferRepository.findByPreAuthorizedCode(UUID.fromString(preAuthCode)).orElseThrow();
        var mgmt = credentialOffer.getCredentialManagement();
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
        if (isDpopUnused(dpop)) {
            return;
        }
        var dpopJwt = demonstratingProofOfPossessionValidationService.parseDpopJwt(dpop, request);
        var credentialManagement = oAuthService.getCredentialManagementByAccessToken(accessToken);
        demonstratingProofOfPossessionValidationService.validateAccessTokenBinding(accessToken, dpopJwt, credentialManagement.getDpopKey());
    }

    /**
     * Extend OpenIdConfiguration with the signing algorithms supported for DPoP.
     *
     * @param openIdConfiguration The configuration to be extended
     * @return the openidConfiguration with added dpop_signing_alg_values_supported
     */
    public OpenIdConfigurationDto addSigningAlgorithmsSupported(OpenIdConfigurationDto openIdConfiguration) {
        var builder = openIdConfiguration.toBuilder();
        builder.dpop_signing_alg_values_supported(DemonstratingProofOfPossessionUtils.getSupportedAlgorithms());
        return builder.build();
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
    @Transactional
    public void refreshDpop(String refreshToken, String dpop, ServletServerHttpRequest request) {
        if (isDpopUnused(dpop)) {
            return;
        }
        var dpopJwt = demonstratingProofOfPossessionValidationService.parseDpopJwt(dpop, request);
        var credentialManagement = oAuthService.getUnrevokedCredentialOfferByRefreshToken(refreshToken);
        demonstratingProofOfPossessionValidationService.validateBoundPublicKey(dpopJwt, credentialManagement.getDpopKey());
        credentialManagement.setDPoPKey(dpopJwt.getHeader().getJWK().toJSONObject());
        credentialManagementRepository.save(credentialManagement);
    }


    /**
     * Checks if the dpop has not been included and is set to be optional.
     */
    private boolean isDpopUnused(@Nullable String dpop) {
        if (StringUtils.isBlank(dpop)) {
            if (applicationProperties.isDpopEnforce()) {
                throw new DemonstratingProofOfPossessionException("Authorization server requires nonce in DPoP proof",
                        DemonstratingProofOfPossessionError.USE_DPOP_NONCE);
            } else {
                // Not enforced, so not having a dpop is fine
                return true;
            }
        }
        return false;
    }

}