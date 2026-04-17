# Migration Guide: v2.4.x → v3.0.0

This guide helps you migrate from **v2.4.x** to **v3.0.0** of the Generic Issuer Service.

It is based on the **v3.0.0** section in `CHANGELOG.md` ("latest (3.0.0)").

## Compatibility summary

- **Wallets / OID4VCI clients:** may need changes due to removed endpoints and more strictly spec-compliant error
  handling.
- **Issuer business systems (management API clients / callbacks):** may need changes because some response DTOs and
  callback timing semantics changed.
- **Operators:** should review new environment variables and crypto / metadata validation changes.

## Breaking changes

### 1) `c_nonce` removed from token response (`OAuthTokenDto`)

**What changed**

- `c_nonce` was removed from `OAuthTokenDto`.
- The nonce must now be retrieved from the **nonce endpoint**.
- The `nonce` column was removed from the `credential_offer` table.

**What you need to do**

- If your wallet/client expected `c_nonce` in the token response, update it to call the nonce endpoint.
- Ensure DB migrations have been applied (Flyway) since the schema changed.

### 2) Deprecated OID4VCI Draft 13 endpoints removed

**What changed**

- Draft 13 endpoints are removed.

**What you need to do**

- Update any client integrations still calling draft-13 URLs to the supported OID4VCI 1.0 endpoints (The documentation
  has been updated accordingly).

### 3) `did:jwk` no longer supported

**What changed**

- Support for `did:jwk` for cryptographic_binding_methods_supported in issuer metadata was removed because it is no longer part of the Swiss profiles.

**What you need to do**

- Ensure your issuer DID uses supported DID methods.

## Behavioral / functional changes

### 4) SD-JWT disclosure handling: recursion vs flattening

**What changed**

- Added support for **array disclosures** and for handling objects/arrays either:
    - **without recursion** (`recursiveDisclosureEnabled=false`, default): objects are flattened; arrays are emitted
      like:

```json
{
    "_sd": [
        "..."
    ],
    "languages": [
        {
            "...": "some digest"
        }
    ]
}
```

- **with recursion** (`recursiveDisclosureEnabled=true`): objects and arrays are emitted according to the SD-JWT
  specification.

**What you need to do**

- At the moment only the default non-recursive behavior is used by the wallet, but you can enable recursive disclosure
  handling via the new
  `recursiveDisclosureEnabled` in order to check the implementation.

### 5) Error responses: OID4VCI 1.0 compliant error codes

**What changed**

- Error codes for `credential_endpoint` and `deferred_credential_endpoint` error responses are now **OID4VCI 1.0
  compliant**.
- Most notably: `error_code` is now **lower case**.

**What you need to do**

- Update clients that match error codes case-sensitively.
- Update automated tests that assert exact error payloads.

### 6) Nonces are validated to originate from this service

**What changed**

- Nonces are now validated so that client-side generated nonces are rejected.

**What you need to do**

- Ensure wallets always use the nonce issued by this service (via nonce endpoint), not locally generated values.

### 7) DPoP behavior tightened

**What changed**

- DPoP now accepts the correct authorization header, without breaking previously used DPoP header.
- Downgrading is prevented once DPoP was used.

**What you need to do**

- If you’re rolling out DPoP gradually, test upgrade/downgrade behavior and ensure clients don’t attempt downgrade
  flows.

### 8) Issuer metadata: stricter `logo_uri` validation

**What changed**

- Additional validation was added for issuer metadata `logo_uri`:
    - must be a **data URI**
    - must be `image/png` or `image/jpeg`
    - examples: `data:image/png;base64,...` or `data:image/jpeg;base64,...`

**What you need to do**

- Update issuer metadata to ensure `logo_uri` is a valid data URI of the allowed types. If not update the metadata
  accordingly.

## Operational / deployment changes

### 9) Optional registry health checks

**What changed**

- New env var `REGISTRY_HEALTH_CHECKS_ENABLED` was added to enable status registry health checks.
    - Check if the status registry can be reached with the configured credentials
    - Check if the did can be resolved from the identifier registry

**What you need to do**

- Decide whether to enable it and ensure the registry endpoint and credentials are configured.

### 10) Metadata claim descriptor path validation improved

**What changed**

- Validation of metadata claim descriptor paths now correctly supports claims path pointers and validates according to
  specs.
- Metadata claims are for the moment provided under 2 different paths in the metadata :
    - The new `credential_metadata.claims` which:
        - Now uses claims path pointers which are already known from OID4VP DCQL in the verifier
        - If credential metadata claims are set, the issuer validates incomming subject_data against the claim
          descriptors and rejects the request if the validation fails.
    - and the old path `claims` with the same format as before (for backward compatibility reasons).
      **What you need to do**

- If you have custom claim descriptors, validate them against the updated implementation.
- Add the `credential_metadata.claims` to your issuer metadata. Be aware that if you set the claims the validation will
  use these values instead of the legacy `claims` path.

Old way -> Still used for `claims` as fallback in issuer metadata, but the new way MUST be used, as the wallet will soon stop support for the old style of claims.
for `credential_metadata.claims`:

```json
{
    "claims": {
        "type": {
            "mandatory": true,
            "value_type": "string"
        },
        "name": {
            "mandatory": true,
            "value_type": "string"
        },
        "average_grade": {
            "mandatory": false,
            "value_type": "number"
        },
        "languages": {
            "mandatory": false,
            "value_type": "array"
        }
    }
}
```

New way with claims path pointers:

```json
{
    "credential_metadata": {
        "claims": [
            {
                "mandatory": true,
                "path": [
                    "type"
                ]
            },
            {
                "mandatory": true,
                "path": [
                    "name"
                ]
            },
            {
                "mandatory": false,
                "path": [
                    "average_grade"
                ]
            },
            {
                "path": [
                    "languages",
                    null
                ]
            }
        ]
    }
}
```

## Upgrade checklist

- [ ] Apply DB migrations (Flyway) and verify the `credential_offer.nonce` column is removed.
- [ ] Update OID4VCI clients to use the nonce endpoint (don’t expect `c_nonce` in token response).
- [ ] Verify no client uses draft-13 endpoints.
- [ ] Verify issuer metadata cryptographic_binding_methods_supported is not `did:jwk`.
- [ ] Validate issuer metadata `logo_uri` is a data URI (png/jpeg only).
- [ ] Update client error-handling for OID4VCI 1.0 compliant (lower-case) error codes.
- [ ] Decide whether to enable `REGISTRY_HEALTH_CHECKS_ENABLED`.
- [ ] Update claims in issuer metadata to use new `credential_metadata.claims` with claims path pointers and ensure
  validation is correct.

## Reference

- `CHANGELOG.md` → section: `latest (3.0.0)`