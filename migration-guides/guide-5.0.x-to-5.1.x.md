# Migration Guide: v5.0.x to v5.1.x

This guide helps you migrate from **v5.0.x** to **v5.1.x** of the Swiyu Issuer Service.
It is based on the **[5.1.0]** section in `CHANGELOG.md`.

## Compatibility summary

- **Issuance clients / OID4VCI wallets:**
    - Tenant-specific issuer metadata now responds with `410 GONE` instead of `500 INTERNAL ERROR` when the latest
      credential offer of the tenant is `EXPIRED` or `CANCELLED`.
    - The `iss` claim in Key Attestation JWTs is ignored (it may be missing or present), as defined in
      swiss-profile-anchor 1.0.
    - Key Attestation no longer resolves DID documents from outside the accepted base registry.

- **Business issuers (renewal):**
    - The renewal request (`RenewalRequestDto`) sent to the business issuer contains a new optional property
      `configuration_id`. It holds the requested credential configuration and allows the business issuer to return a
      different configuration than the one used for the initial credential offer. Existing business issuers can ignore
      the property.

- **Operators / DevOps:**
    - **Issuer metadata:** `cryptographic_binding_methods_supported` and `proof_types_supported` are now mandatory for
      every credential configuration. See [breaking change 1](#1-cryptographic_binding_methods_supported-and-proof_types_supported-are-mandatory).
    - **Default limits:** The default values for `MAX_COMPRESSED_CIPHER_TEXT_LENGTH` and
      `MAX_DECOMPRESSED_PAYLOAD_LENGTH` changed from 20 MiB to 20 MB. See [change 2](#2-default-sizes-for-encrypted-messages-in-mb-instead-of-mib).
    - **New optional environment variable:** `ENABLE_SUSPENDED_RENEWAL` (default: `false`) allows suspended credentials to
      be renewed. Refer to the renewal section in the `README.md` before enabling it.

## Breaking changes

### 1. `cryptographic_binding_methods_supported` and `proof_types_supported` are mandatory

In compliance with the swiss-profile-issuance (and in contrast to the OID4VCI standard), unbound credentials are no
longer accepted. Each credential configuration in the issuer metadata must contain:

- `cryptographic_binding_methods_supported`: non-empty array, only `jwk` is supported.
- `proof_types_supported`: exactly one proof type, only `jwt` is supported.

A credential configuration missing one of these properties fails the metadata validation.

**Before (v5.0.x) - properties optional:**

```json
"credential_configurations_supported": {
    "university_example_sd_jwt": {
        "format": "dc+sd-jwt",
        "vct": "university_example_sd_jwt"
    }
}
```

**After (v5.1.x) - properties mandatory:**

```json
"credential_configurations_supported": {
    "university_example_sd_jwt": {
        "format": "dc+sd-jwt",
        "vct": "university_example_sd_jwt",
        "cryptographic_binding_methods_supported": [ "jwk" ],
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": [ "ES256" ]
            }
        }
    }
}
```

See [example_issuer_metadata.json](../issuer-application/src/main/resources/example_issuer_metadata.json) for a full
example.

## Other changes requiring attention

### 2. Default sizes for encrypted messages in MB instead of MiB

The defaults follow the swiss-profile and are now expressed in decimal megabytes.

| Variable                          | v5.0.x                 | v5.1.x                 |
|-----------------------------------|------------------------|------------------------|
| `MAX_COMPRESSED_CIPHER_TEXT_LENGTH` | `20971520` (20 MiB)    | `20000000` (20 MB)     |
| `MAX_DECOMPRESSED_PAYLOAD_LENGTH`   | `20971520` (20 MiB)    | `20000000` (20 MB)     |

Only deployments relying on the defaults are affected. If you need the previous limit, set the variables explicitly.

### 3. `410 GONE` for metadata of expired or cancelled credential offers

Clients fetching the tenant-specific issuer metadata (`/.well-known/openid-credential-issuer`) must handle
`410 GONE` when the latest credential offer of the tenant is `EXPIRED` or `CANCELLED`. Previously this resulted in
`500 INTERNAL ERROR`.
