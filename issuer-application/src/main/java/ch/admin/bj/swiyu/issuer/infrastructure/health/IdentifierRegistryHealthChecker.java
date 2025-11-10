package ch.admin.bj.swiyu.issuer.infrastructure.health;


import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
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

    /** Resolver used to attempt key / DID resolution. Must be provided as a Spring Bean. */
    private final KeyResolver keyResolver; // injected via Lombok-generated constructor

    /** DID (or DID key) identifying the issuer. Provided by property 'application.issuer-id'. */
    @Value("${application.issuer-id}")
    private String issuerDid;

    /** List of trusted attestation provider DIDs (or DID keys). Provided by 'application.trusted-attestation-providers'. */
    @Value("${application.trusted-attestation-providers}")
    private List<String> trustedAttestationDids;

    /**
     * Performs the health logic
     * Note: Overall status (UP/DOWN) is determined here, but the scheduling + caching of the result
     * is handled by {@link CachedHealthChecker}.
     */
    @Override
    protected void performCheck(Health.Builder builder) {
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
        try {
            keyResolver.resolveKey(did);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}