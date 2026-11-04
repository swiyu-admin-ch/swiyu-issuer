# Migration Guide: v4.0.x to v5.0.x

This guide helps you migrate from **v4.0.x** to **v5.0.x** of the Swiyu Issuer Service.
It is based on the **[5.0.0]** section in `CHANGELOG.md`.

## Compatibility summary

- **Issuance clients / OID4VCI wallets:**
    - The `vc+sd-jwt` credential format (pre OID4VCI Draft 13) is no longer supported. Only `dc+sd-jwt` format is
      accepted.
    - New optional credential configuration property `credential_refresh_disabled` (boolean) can now be set per
      credential type to disable the renewal flow for specific credentials. Wallets should check this property and not
      display renewal options for disabled credentials. For example see
      the [example_issuer_metadata.json](../issuer-application/src/main/resources/example_issuer_metadata.json#445).
    - New optional `tx_code` support for enhanced security flows: credential offers can now be configured with
      `tx_code_config.use_tx_code = true` to use a secondary code sent through a different channel. This is done inside
      CreateCredentialOfferRequest object.
      ```json
      {
        "metadata_credential_supported_id": "university_example_sd_jwt",
        "credential_subject_data": {...},
        "tx_code_config": {
          "use_tx_code": true
        }
      }
      ```
    - Metadata no longer includes empty `proof_types_supported` maps when not provided.

- **Operators / DevOps:**
    - **Environment variables removed:** The deprecated caching configuration variables are no longer supported:
        - `caching.publicKeyCacheTTL` (use `caching.public-key-cache-ttl-ms` instead)
        - `caching.encryptionMetadataCacheTTL` (use `caching.encryption-metadata-cache-ttl-ms` instead)
    - **Credential renewal:** The renewal flow is now enabled exclusively by setting
      `BUSINESS_ISSUER_RENEWAL_API_ENDPOINT`. Not setting this value (the default) disables renewal functionality. The
      `RENEWAL_FLOW_ENABLED` environment variable is no longer used. Business Issuers must respond to the HTTP call at
      this endpoint with a RenewalResponse Object containing information for the renewed VC.
    - **API Key support for renewal:** Optionally, API keys can now be set for Credential Renewal calls to the business
      issuer using:
        - `BUSINESS_ISSUER_RENEWAL_API_KEY_HEADER`
        - `BUSINESS_ISSUER_RENEWAL_API_KEY_VALUE`

## Breaking changes

### 1. Credential format: `vc+sd-jwt` removed, only `dc+sd-jwt` supported

This is purely informational. As Integrator no action is required.

**Before (v4.0.x):**  
The issuer supported both `vc+sd-jwt` (pre OID4VCI Draft 13) and `dc+sd-jwt` formats as an "Expand-Migrate-Contract"
strategy.

```json
{
    "credential_configurations_supported": {
        "ch.admin.swiyu.example": {
            "format": "vc+sd-jwt"
        }
    }
}