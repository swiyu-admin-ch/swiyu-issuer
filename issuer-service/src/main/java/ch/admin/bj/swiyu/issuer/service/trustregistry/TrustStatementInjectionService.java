package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

/**
 * Service responsible for injecting Trust Protocol 2.0 trust statements into
 * {@link IssuerMetadata} before it is returned to the wallet.
 *
 * <p>Injects two kinds of trust statement JWTs:</p>
 * <ul>
 *   <li><strong>idTS</strong> – Identity Trust Statement on the root level of the issuer metadata
 *       ({@code credential_issuer_identity_trust_statement}).</li>
 *   <li><strong>piaTS</strong> – Protected Issuance Authorization Trust Statement on each
 *       {@link CredentialConfiguration} that requires key attestation
 *       ({@code protected_issuance_authorization_trust_statement}).</li>
 * </ul>
 *
 * <p>Only active when a {@link TrustStatementCacheService} bean is present
 * (i.e. {@code swiyu.trust-registry.api-url} is configured).</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnBean(TrustStatementCacheService.class)
public class TrustStatementInjectionService {

    private final TrustStatementCacheService trustStatementCacheService;

    /**
     * Optional validator for signature verification at inject time.
     * When present, each cached trust statement JWT is verified against the
     * Trust Registry's current DID Document before injection. This ensures
     * key rotations are detected immediately, without waiting for cache expiry.
     * On failure the cache entry is invalidated so a fresh statement is fetched next time.
     */
    private final Optional<TrustStatementValidator> trustStatementValidator;

    /**
     * Injects the idTS and piaTS trust statement JWTs into the given issuer metadata.
     *
     * <p>Before each injection, the cached JWT's signature is re-verified against the
     * Trust Registry's current DID Document (Phase 2 of Flow B). If verification fails,
     * the cache entry is invalidated and the statement is omitted from this response.</p>
     *
     * @param issuerMetadata the mutable issuer metadata object to enrich
     * @param issuerDid      the effective issuer DID (respects {@code ConfigurationOverride})
     */
    public void injectTrustStatements(IssuerMetadata issuerMetadata, String issuerDid) {
        injectIdentityTrustStatement(issuerMetadata, issuerDid);
        injectProtectedIssuanceAuthorizationTrustStatements(issuerMetadata, issuerDid);
    }

    /**
     * Fetches the idTS JWT, verifies its signature, and sets it on the root level
     * of the issuer metadata. On signature failure the cache is invalidated.
     *
     * @param issuerMetadata the metadata to update
     * @param issuerDid      the issuer DID to look up in the trust registry
     */
    private void injectIdentityTrustStatement(IssuerMetadata issuerMetadata, String issuerDid) {
        String idTs = trustStatementCacheService.getIdentityTrustStatement(issuerDid);
        if (idTs == null) {
            log.debug("No idTS available for issuer {} – skipping injection", issuerDid);
            return;
        }
        if (!verifySignatureOrInvalidate(idTs, "idTS", issuerDid)) {
            return;
        }
        issuerMetadata.setCredentialIssuerIdentityTrustStatement(idTs);
    }

    /**
     * Fetches the piaTS JWT, verifies its signature, and injects it into every
     * {@link CredentialConfiguration} that requires key attestation.
     * On signature failure the cache is invalidated.
     *
     * @param issuerMetadata the metadata whose credential configurations should be updated
     * @param issuerDid      the issuer DID to look up in the trust registry
     */
    private void injectProtectedIssuanceAuthorizationTrustStatements(IssuerMetadata issuerMetadata, String issuerDid) {
        Map<String, CredentialConfiguration> configs = issuerMetadata.getCredentialConfigurationSupported();
        if (configs == null || configs.isEmpty()) {
            return;
        }

        boolean anyProtected = configs.values().stream().anyMatch(this::isProtectedVcConfiguration);
        if (!anyProtected) {
            return;
        }

        String piaTs = trustStatementCacheService.getProtectedIssuanceAuthorizationTrustStatement(issuerDid);
        if (piaTs == null) {
            log.debug("No piaTS available for issuer {} – skipping injection into protected credential configurations", issuerDid);
            return;
        }
        if (!verifySignatureOrInvalidate(piaTs, "piaTS", issuerDid)) {
            return;
        }

        configs.values().stream()
                .filter(this::isProtectedVcConfiguration)
                .forEach(config -> config.setProtectedIssuanceAuthorizationTrustStatement(piaTs));
    }

    /**
     * Verifies the signature of the given trust statement JWT via
     * {@link TrustStatementValidator#validateSignature(String)}.
     * If verification fails, the cache entry for the issuer DID is invalidated
     * so that a fresh statement is fetched on the next request.
     *
     * @param jwt       the trust statement JWT to verify
     * @param type      statement type label for logging ("idTS" or "piaTS")
     * @param issuerDid issuer DID for cache invalidation and logging
     * @return {@code true} if verification succeeded or no validator is configured;
     *         {@code false} if verification failed (cache is invalidated)
     */
    private boolean verifySignatureOrInvalidate(String jwt, String type, String issuerDid) {
        if (trustStatementValidator.isEmpty()) {
            return true;
        }
        try {
            trustStatementValidator.get().validateSignature(jwt);
            return true;
        } catch (JwtValidatorException e) {
            log.warn("{} signature verification failed for issuer {} – invalidating cache: {}", type, issuerDid, e.getMessage());
            trustStatementCacheService.invalidateAllTrustStatements(issuerDid);

            return false;
        }
    }

    /**
     * Returns {@code true} if the credential configuration represents a Protected VC,
     * i.e. if at least one supported proof type has a {@code key_attestations_required} entry.
     *
     * @param config the credential configuration to inspect
     * @return {@code true} if key attestation is required for any proof type
     */
    private boolean isProtectedVcConfiguration(CredentialConfiguration config) {
        return config.getProofTypesSupported().values().stream()
                .anyMatch(proofType -> proofType.getKeyAttestationRequirement() != null);
    }
}

