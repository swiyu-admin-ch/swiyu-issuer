package ch.admin.bj.swiyu.issuer.infrastructure.health;


import ch.admin.bj.swiyu.didresolveradapter.DidResolverAdapter;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.didresolver.Did;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Health checker that validates the reachability / resolvability of DID (or DID key) identifiers
 * configured for the issuer itself as well as the trusted attestation providers.
 */
@Component
@RequiredArgsConstructor
public class IdentifierRegistryHealthChecker extends CachedHealthChecker {

    private final DidResolverAdapter didResolverAdapter;


    private final ApplicationProperties applicationProperties;


    /**
     * Performs the health logic
     * Note: Overall status (UP/DOWN) is determined here, but the scheduling + caching of the result
     * is handled by {@link CachedHealthChecker}.
     */
    @Override
    protected void performCheck(Health.Builder builder) {

        /* DID (or DID key) identifying the issuer. Provided by property 'application.issuer-id'. */
        String issuerDid = applicationProperties.getIssuerId();

        /* List of trusted attestation provider DIDs (or DID keys). Provided by 'application.trusted-attestation-providers'. */
        List<String> trustedAttestationDids = applicationProperties.getTrustedAttestationProviders();

        List<String> failed = new ArrayList<>();

        // Check issuer DID
        if (!resolveDid(issuerDid)) {
            failed.add(issuerDid);
        }

        // Check verifier DIDs
        for (String did : trustedAttestationDids) {
            if (!resolveDid(did)) {
                failed.add(did);
            }
        }

        if (failed.isEmpty()) {
            builder.withDetail("resolved", "all DIDs ok");
        } else {
            builder.down().withDetail("failedDids", failed);
        }
    }

    /**
     * Attempts to resolve the supplied DID (or DID key) via the {@link KeyResolver}.
     * Returns true if resolution succeeded, false otherwise.
     *
     * @param did DID or DID key identifier to resolve.
     * @return true if resolution is successful (no exception), false otherwise.
     */
    private boolean resolveDid(String did) {
        if (did == null || did.isBlank()) {
            return false;
        }
        try (Did resolved = new Did(did)) {
            final String url = resolved.getUrl();
            DidDoc didDoc = didResolverAdapter.resolveDid(url, null);

            return didDoc != null;
        } catch (Exception e) {
            return false;
        }
    }
}