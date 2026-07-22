package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.date.TimeUtil;
import ch.admin.bj.swiyu.issuer.service.did.DidKeyResolverFacade;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import ch.admin.bj.swiyu.statuslist.TokenStatusListVerifier;
import ch.admin.bj.swiyu.statuslist.dto.StatusVerificationResultDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListMapper;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListReferenceDto;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.text.ParseException;
import java.util.concurrent.TimeUnit;

/**
 * Validates Trust Statement JWTs (idTS and piaTS) using the two-step Flow B of
 * {@link DidJwtValidator}, split across two distinct phases:
 *
 * <ol>
 *   <li><strong>Pre-cache validation</strong> ({@link #validateAllowlist(String)}):
 *       Called at fetch time. Checks that the JWT's {@code kid} resolves to a DID URL
 *       on the configured Trust Registry allowlist. Fast – no HTTP call. Prevents
 *       malicious JWTs with foreign DIDs from ever entering the cache.</li>
 *   <li><strong>Pre-inject validation</strong> ({@link #validateSignature(String)}):
 *       Called on every metadata response, just before the cached JWT is injected.
 *       Fetches the Trust Registry's DID Document fresh and verifies the signature.
 *       This ensures key rotations on the Trust Registry side are detected immediately,
 *       without waiting for the cache TTL to expire.</li>
 * </ol>
 *
 * <p>On signature failure the caller is expected to invalidate the cache entry via
 * {@link TrustStatementCacheService#invalidateAllTrustStatements(String)} so that a fresh
 * statement is fetched on the next request.</p>
 *
 * <p>Only active when {@code swiyu.trust-registry.api-url} is configured.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnExpression("'${swiyu.trust-registry.api-url:}'.length() > 0")
public class TrustStatementValidator {

    private final DidJwtValidator trustStatementDidJwtValidator;
    private final SwiyuProperties swiyuProperties;

    private final StatusListCacheService statusListCacheService;
    private final DidKeyResolverFacade keyLoader;
    private final TokenStatusListVerifier statusListVerifier;
    private final DidKidParser didKidParser = new DidKidParser();


    /**
     * Validates the Trust Statement JWT and (if any) associated Status Lists. Computes the validity window
     * (the time the trust statement can be cached for) from the
     * minimum validity of the Trust Statement expiry, Status List Expiry, Status List TTL or Trust Statement Cache TTL.
     * <br>
     * Does NOT validate if the Trust Statement is correct in the context it is being used!
     *
     * @param jwtString
     * @return TrustStatementValidationResult containing if the trust statement has a valid state and the milliseconds the trust statement can be cached
     */
    public TrustStatementValidationResult trustStatementValidityWindow(String jwtString) {
        if (jwtString == null) {
            return new TrustStatementValidationResult(false, 0);
        }
        try {
            // Get all required parts & verify them
            String didUrl = trustStatementDidJwtValidator.getAndValidateResolutionUrl(jwtString);
            String didString = trustStatementDidJwtValidator.getDidString(jwtString);
            log.debug("Trust statement allowlist check passed - DID: {}, URL: {}", didString, didUrl);
            String kid = didKidParser.extractKidFromHeader(jwtString);
            SignedJWT trustStatementJWT = SignedJWT.parse(jwtString);
            JWK trustStatementKey = keyLoader.resolveKey(kid);
            trustStatementDidJwtValidator.validateJwt(jwtString, trustStatementKey);
            log.debug("Trust statement validation passed - DID: {}, URL: {}", didString, didUrl);
            TokenStatusListReferenceDto reference = TokenStatusListMapper.toTokenStatusListReference(trustStatementJWT.getJWTClaimsSet().getClaims());
            TokenStatusListTokenDto statusList = statusListCacheService.getTokenStatusListTokenByUri(reference.getReferencedStatusListUri());
            StatusVerificationResultDto statusListState = statusListVerifier.verifyStatus(reference, statusList);

            // Compute TTL in Nanoseconds
            long minimumTimeoutNs = TimeUnit.SECONDS.toNanos(swiyuProperties.trustRegistry().maxCacheTtlSeconds());
            minimumTimeoutNs = TimeUtil.minNanosUntilExpiry(minimumTimeoutNs, TimeUtil.secondsToNanos(statusList.getExp()));
            minimumTimeoutNs = TimeUtil.minNanosUntilExpiry(minimumTimeoutNs, trustStatementJWT.getJWTClaimsSet().getExpirationTime());
            // Substract the clock skew from expiration time to ensure that we fetch sufficiently soon the new Trust Statement
            minimumTimeoutNs = Math.max(0, minimumTimeoutNs - swiyuProperties.trustRegistry().clockSkewBufferSeconds());
            minimumTimeoutNs = TimeUtil.minWithNullable(minimumTimeoutNs, TimeUtil.secondsToNanos(statusList.getTtl()));
            log.debug("Trust statement state validation completed - Validity: {} Cache TTL {} - DID: {}, URL: {}", statusListState.valid(), minimumTimeoutNs, didString, didUrl);

            // If we reached this point the status list state hold the information whether the trust statement can be used. Either way we should not reprocess it until the timeout is through
            return new TrustStatementValidationResult(statusListState.valid(), minimumTimeoutNs);

        } catch (IllegalArgumentException | ParseException | IOException | JwtValidatorException e) {
            log.info("Malformed or invalid Trust Statement detected: {} - Ignoring it", jwtString, e);
            return new TrustStatementValidationResult(false, TimeUtil.secondsToNanos(swiyuProperties.trustRegistry().requestBackoffSeconds()));
        }
    }

    /**
     * @param isValid        is the statement validated valid & to be used
     * @param valditiyWindow how long this validation result may be used in nanoseconds
     */
    public record TrustStatementValidationResult(boolean isValid, long valditiyWindow) {
    }
}
