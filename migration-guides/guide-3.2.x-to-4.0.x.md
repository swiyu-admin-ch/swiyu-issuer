# Migration Guide: v3.2.x to v4.0.x

This guide helps you migrate from **v3.2.x** to **v4.0.x** of the Swiyu Issuer Service.  
It is based on the **[4.0.0]** section in `CHANGELOG.md`.

## Compatibility summary

- **Issuance clients / OID4VCI wallets:**
    - Wallets consuming status list tokens (`statuslist+jwt`) must now respect the new `ttl`, `exp`, and `iat` claims
      for cache lifetime and validity checks.
    - The expanded `enc_values_supported` now includes `A256GCM` in addition to `A128GCM`.
    - The `claims` field in `credential_configurations_supported` has been **removed** — use`credential_metadata.claims`
      instead.
    - `client_metadata.display` can **no longer** be an empty list; set it to `null` if unused.
    - `client_metadata.display.name` is now **required** (not nullable).
    - `background_image` and `text_color` in `client_metadata.display` are now **deprecated** (marked `NOT SUPPORTED` in
      the Swiss Profile).
    - `vct#integrity` is **removed** from issuer metadata — use `vct_metadata_uri` and `vct_metadata_uri#integrity`
      instead.

- **Operators / DevOps:**
    - **Trust registry** integration simplified: `SWIYU_TRUST_REGISTRY_CUSTOMER_KEY` and
      `SWIYU_TRUST_REGISTRY_CUSTOMER_SECRET` are **removed** (read-only registry requires no authentication).
    - **Status list configuration** expanded: new properties `statusListCacheTime` and `statusListExpirationTime` must
      be set under `application.status-list`.
    - **Dependency verification** now enforced: PGP signatures of all third-party Maven artifacts are checked during
      build. CI/CD must cache PGP keys to avoid download overhead.
    - **Container image signing** introduced: published images are now signed with Cosign (keyless OIDC). Consumers can
      verify image authenticity via `cosign verify`.

## Breaking changes

### 1. Metadata: removal of `claims` from `credential_configurations_supported`

**Before (v3.2.x):**  
Credential metadata exposed a top-level `claims` field within `credential_configurations_supported`:

```json
{
    "credential_configurations_supported": {
        "ch.admin.swiyu.example": {
            "format": "vc+sd-jwt",
            "claims": {
                "given_name": {
                    "display": [
                        ...
                    ]
                },
                "family_name": {
                    "display": [
                        ...
                    ]
                }
            }
        }
    }
}
```

**After (v4.0.0):**  
The `claims` field is **removed**. All claims details must now be provided under `credential_metadata.claims`:

```json
{
    "credential_configurations_supported": {
        "ch.admin.swiyu.example": {
            "format": "vc+sd-jwt",
            "credential_metadata": {
                "claims": {
                    "given_name": {
                        "display": [
                            ...
                        ]
                    },
                    "family_name": {
                        "display": [
                            ...
                        ]
                    }
                }
            }
        }
    }
}
```

**Action required:**  
Update your issuer metadata configuration to move all `claims` entries into the nested `credential_metadata.claims`
structure.

### 2. Metadata: `client_metadata.display` validation tightened

**Changes:**

- **Cannot be an empty list** — if you do not want to use `display`, set it to `null` instead of `[]`.
- **`name` is now required** — `client_metadata.display.name` must be present and non-null (
  per [OID4VCI specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p)).
- **`background_image` and `text_color` are deprecated** — marked as `NOT SUPPORTED` in the Swiss Profile and should not
  be used.

**Action required:**

- If your metadata includes an empty `display` list, replace it with `null`.
- Ensure every `display` entry contains a valid `name` field.
- Remove or stop relying on `background_image` and `text_color` if present.

### 3. Metadata: removal of `vct#integrity`

**Before (v3.2.x):**  
Issuer metadata included a top-level `vct#integrity` field for credential type integrity validation.

**After (v4.0.0):**  
`vct#integrity` is **removed**. Use the nested `vct_metadata_uri` and `vct_metadata_uri#integrity` fields instead.

**Action required:**  
Update your metadata configuration to use `vct_metadata_uri` and `vct_metadata_uri#integrity` in place of the removed
`vct#integrity` field.

### 4. Environment variables: trust registry authentication removed

**Before (v3.2.x):**  
Trust registry integration required authentication via:

```bash
SWIYU_TRUST_REGISTRY_CUSTOMER_KEY=your-key
SWIYU_TRUST_REGISTRY_CUSTOMER_SECRET=your-secret
```

**After (v4.0.0):**  
The trust registry is **read-only** and does not require authentication. These variables are **removed**.

**Action required:**  
Remove `SWIYU_TRUST_REGISTRY_CUSTOMER_KEY` and `SWIYU_TRUST_REGISTRY_CUSTOMER_SECRET` from your deployment
configuration (docker-compose, Kubernetes manifests, Helm values, etc.).

### 5. Configuration: new status list properties required

**Before (v3.2.x):**  
Status list tokens were generated without explicit TTL or expiration configuration.

**After (v4.0.0):**  
Status list tokens (`statuslist+jwt`) now include `ttl`, `exp`, and `iat` claims. You must configure:

- `statusListCacheTime` — TTL used by wallet status list caches (ISO 8601 duration, e.g., `PT1H` for 1 hour).
- `statusListExpirationTime` — Expiration duration for generated status lists (ISO 8601 duration, e.g., `PT24H` for 24
  hours).

**Action required:**  
Add the new properties to your `application.yml` under `application.status-list`:

```yaml
application:
    status-list:
        statusListCacheTime: PT1H      # 1 hour cache TTL
        statusListExpirationTime: PT24H # 24 hours until expiration
```

Adjust the durations according to your operational requirements.

## Improvements & fixes

### Security enhancements

- **Container image signing:** All published images (both hardened and unhardened variants) are now automatically signed
  with [Cosign](https://docs.sigstore.dev/) using keyless OIDC signing. Signatures are bound to the immutable image
  digest and published to the Sigstore transparency log.

  **Verify image authenticity:**
  ```bash
  cosign verify \
    --certificate-identity-regexp="https://github.com/swiyu-admin-ch/swiyu-issuer/.*" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
    ghcr.io/swiyu-admin-ch/swiyu-issuer:4.0.0
  ```

- **Dependency verification:** The build now integrates `pgpverify-maven-plugin` to cryptographically verify PGP
  signatures of all third-party dependencies. Builds fail if an artifact has no signature or an invalid signature. PGP
  keys are cached in CI/CD for performance.

## Migration checklist

- [ ] **Update metadata configuration:**
    - [ ] Move all `claims` from `credential_configurations_supported` to `credential_metadata.claims`.
    - [ ] Replace empty `client_metadata.display` lists with `null`.
    - [ ] Ensure every `display` entry has a valid `name` field.
    - [ ] Remove `background_image` and `text_color` from `client_metadata.display` if present.
    - [ ] Replace `vct#integrity` with `vct_metadata_uri` and `vct_metadata_uri#integrity`.

- [ ] **Update environment variables:**
    - [ ] Remove `SWIYU_TRUST_REGISTRY_CUSTOMER_KEY` from all deployment manifests.
    - [ ] Remove `SWIYU_TRUST_REGISTRY_CUSTOMER_SECRET` from all deployment manifests.

- [ ] **Add status list configuration:**
    - [ ] Add `statusListCacheTime` to `application.status-list` in your `application.yml`.
    - [ ] Add `statusListExpirationTime` to `application.status-list` in your `application.yml`.

- [ ] **Verify build pipeline:**
    - [ ] Ensure CI/CD caches PGP keys to avoid redundant downloads during dependency verification.
    - [ ] Test that the build passes PGP signature verification for all third-party dependencies.

- [ ] **Optional: verify container image signatures:**
    - [ ] Install Cosign in your deployment pipeline if you want to verify image authenticity.
    - [ ] Add `cosign verify` step before pulling/deploying images.

- [ ] **Test deployment:**
    - [ ] Confirm wallets correctly interpret the new `ttl`, `exp`, and `iat` claims in status list tokens.
    - [ ] Verify that credential issuance works with the updated metadata structure.
    - [ ] Check logs for any warnings about deprecated or removed configuration fields.

## Reference

- [4.0.0] entry in [`CHANGELOG.md`](../CHANGELOG.md).
- [OID4VCI Specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [Cosign Documentation](https://docs.sigstore.dev/)

