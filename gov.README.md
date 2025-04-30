<!--
SPDX-FileCopyrightText: 2025 Swiss Confederation

SPDX-License-Identifier: MIT
-->

## Gov internal usage

### 1. Setup up infrastructure

When deployed in an RHOS setup the issuer-management / issuer-agent setup need the following setup

#### Database

Single postgresql database service needs to be available. Make sure that the following bindings exist between your
database and the application namespace:

- database -> issuer-agent-management: Full
- database -> issuer-agent-oid4vci: Read-Write

#### MAV

The MAV needs to be bound to the application namespace. Make sure the secrets are located in the path *
*default/application_secrets**
and you configured the vault so that it uses the application_secrets as properties

```yaml
vaultsecrets:
  vaultserver: https://my-vault-server.example.com
  serviceaccount: default
  cluster: xyz-cluster
  path: default
  properties:
    - application_secrets
```

### 2. Set the environment variables

Due to the separation of the secret and non-secret variables the location is split. Make sure that you've set at least
the following variables.
Concerning the actual values take a look at the [sample.compose.yml](sample.compose.yml)

> **After this** continue with [status list initialization](README.md#3.-Initialize-the-status-list)

| Location                | issuer-agent-management                                                                                                                                                                                                                                                                   | issuer-agent-oid4vci                                                                                                       |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| GitOps                  | ISSUER_ID<br/>SWIYU_PARTNER_ID<br/>SWIYU_STATUS_REGISTRY_CUSTOMER_KEY<br/>EXTERNAL_URL<br/><br/>LOGGING_LEVEL_CH_ADMIN_BIT_EID<br/>SPRING_APPLICATION_NAME<br/>SWIYU_STATUS_REGISTRY_AUTH_ENABLE_REFRESH_TOKEN_FLOW<br/>SWIYU_STATUS_REGISTRY_TOKEN_URL<br/>SWIYU_STATUS_REGISTRY_API_URL | EXTERNAL_URL<br/>ISSUER_ID<br/>DID_SDJWT_VERIFICATION_METHOD<br/>OPENID_CONFIG_FILE<br/>METADATA_CONFIG_FILE<br/>TOKEN_TTL |
| ManagedApplicationVault | STATUS_LIST_KEY<br/>SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET<br/>SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN                                                                                                                                                                               | SDJWT_KEY                                                                                                                  |
