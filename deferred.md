# Credential Issuance documentation

## Prerequisites for all calls (V1 and V2)

```mermaid
sequenceDiagram
    actor BUSINESS as Business Issuer
    participant ISS as Issuer Agent
    participant DB as Issuer DB
    participant STATUS as Status Registry
    actor WALLET as Holder

# Create status list
    BUSINESS ->>+ ISS: Create status list
    ISS ->>+ DB: Store status list metadata
DB-->>-ISS: 
    ISS->>+STATUS: Create status list entry
STATUS->>-ISS:
ISS-->>-BUSINESS :

# Create offer
BUSINESS->>+ISS: Create offer
ISS->>+DB: Store offer
DB-->>-ISS:
ISS-->>-BUSINESS: Return offer details (incl. deeplink)

# Pass deeplink to WALLET
BUSINESS-->>+WALLET: Pass deeplink to wallet
Note over BUSINESS, WALLET: INFO: Passing the deeplink to the wallet is not part of this service and must be handled by the Business Issuer

loop Status check
BUSINESS->>+ISS: Get status
ISS-->>-BUSINESS:
end

# Get credential
WALLET->>+ISS: Get openid metadata
ISS-->>-WALLET:

WALLET->>+ISS: Get issuer metadata
ISS-->>-WALLET:

WALLET->>+ISS: Get oauth token
ISS-->>-WALLET: Oauth token

WALLET->>+ISS: Redeem offer
ISS->>+DB: Get offer data and status list INFO
DB-->-ISS:
ISS->>+DB: Set STATUS = Deferred
DB-->-ISS:
ISS-->>-WALLET : Transaction id

loop get status
BUSINESS->>+ISS: Get status
ISS-->>-BUSINESS: Status

alt STATUS is Deferred
BUSINESS->>BUSINESS: Some additional process
alt offer data is already set
BUSINESS->>+ISS: Set status READY
else
BUSINESS->>+ISS : Set offer data (STATUS is set to READY)
end
ISS->>DB: Store offer
ISS-->>-BUSINESS:
end
end

loop Get deferred credential
alt STATUS is not READY
WALLET->>+ISS: Get credential from deferred_credential
ISS->>+DB: Get offer data and status list INF
DB-->-ISS:
ISS-->>-WALLET: issuance_pending
else
WALLET->>+ISS: Get credential from deferred_credential
ISS->>+DB: Get offer data and status list INFO
DB-->-ISS:
ISS-->>-WALLET: VC
end
end


loop STATUS is ISSUED
BUSINESS->>+ISS: Get status
ISS->>+DB: Remove offer data
ISS-->>-BUSINESS: Status
end
```

### Create status list entry

Actor: Business Issuer

> [!NOTE]  
> In order to create an offer first you have to initialize a status list. Please store the `statusRegistryUrl` as it is
> needed in later steps and will be referenced as `$STATUS_REGISTRY_URL`.

Explanation of params:

* Type: `TOKEN_STATUS_LIST` is used for token status lists with revocation and suspension.
* `maxLength`: The maximum number of entries in the status list. This is a hard limit and cannot be changed later.
* `config`: Configuration for the status list. The `bits` parameter defines the number of bits used for the status list
  entry.
    - `bits: 2` means that each entry in the status list can have 2 different states (issued, revoked, suspended).

```bash
curl -X 'POST' \
  'http://localhost:8080/management/api/status-list' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
  "type": "TOKEN_STATUS_LIST",
  "maxLength": 100000,
  "config": {
    "bits": 2
  }
}'
```

With the response:

```json
{
    "id": "36f98a79-4be7-4978-bc46-071d8e40343a",
    "statusRegistryUrl": "your new $STATUS_REGISTRY_URL",
    "type": "TOKEN_STATUS_LIST",
    "maxListEntries": 100000,
    "remainingListEntries": 100000,
    "version": "1.0",
    "config": {
        "bits": 2
    }
}
```

### Create credential offer

> [!NOTE]  
> In order to create a deferred credential offer, you need to set `"deferred": true` in the `credential_metadata`.
> In contrast to the normal credential offer, the `credential_subject_data` is not required in the request body, as it
> can be set later, as the content might not be known beforehand (`"credential_subject_data": {}`).

```bash
curl -X 'POST' \
  'http://localhost:8080/management/api/credentials' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "metadata_credential_supported_id": [
    "university_example_sd_jwt"
  ],
  "credential_subject_data": {
    "type": "Bachelor of Science",
    "name":"Data Science",
    "average_grade":"5.33"
  },
  "credential_metadata": {
    "deferred": true
  },
  "offer_validity_seconds": 86400,
  "deferred_offer_validity_seconds": 86400,
  "credential_valid_until": "2030-01-01T19:23:24Z",
  "credential_valid_from": "2025-01-01T18:23:24Z",
  "status_lists": [
    "$STATUS_REGISTRY_URL"
  ]
}'
```

The response will look like this:

```json
{
    "management_id": "6444cd65-f550-4934-af85-1bd295cea1ba",
    "offer_deeplink": "swiyu://?credential_offer=%7B%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%2206b5424f-8baf-4eaa-a770-7fa8ab7a85a7%22%7D%7D%2C%22version%22%3A%221.0%22%2C%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%2F%22%2C%22credential_configuration_ids%22%3A%5B%22university_example_sd_jwt%22%5D%7D"
}
```

> [!NOTE]  
> The `offer_deeplink` can then be passed to the wallet application as QR-Code, which will continue with the credential
> process.
> Please store the `management_id` as it is needed in later steps and will be referenced as `$MANAGEMENT_ID`.
> Also store the `offer_deeplink` as it is needed to create an access token in the next step.

### Get credential offer status with the $MANAGEMENT_ID

```bash
curl -X 'GET' 'http://localhost:8080/management/api/credentials/$MANAGEMENT_ID/status' -H 'accept: application/json'
```

The response will look like this:

```json
{
    "status": "OFFERED"
}
```

### Get Metadata for the credential offer

Actor: Wallet

The wallet will fetch the OpenID Connect metadata from the Issuer to know how to get an access token.

```bash
curl -X 'GET' 'http://localhost:8080/.well-known/openid-configuration' -H 'accept: application/json'
```

With response:

```json
{
    "issuer": "http://localhost:8080",
    "token_endpoint": "http://localhost:8080/oid4vci/api/token"
}
```

The wallet will also fetch the Issuer metadata to know which credential configurations are supported and witch
requirements like Proof Types, Cryptographic Binding Methods, and Claims are available.

```bash
curl -X 'GET' 'http://localhost:8080/oid4vci/.well-known/openid-credential-issuer' -H 'accept: application/json'
```

With response:

```json
{
    "credential_issuer": "http://localhost:8080",
    "credential_response_encryption": {
        "encryption_required": false,
        "alg_values_supported": [
            "ECDH-ES"
        ],
        "enc_values_supported": [
            "A128GCM"
        ]
    },
    "display": [
        {
            "name": "Mein Test Aussteller",
            "locale": "de-CH",
            "logo": {
                "uri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAIAAADYYG7QAAABD0lEQVR4nOyYsUrEQBRFVQYRYYUtZi0UC0vFUrBeYW1sF2E/wU623P8RkTSCf7FFipDaIkxhmkyapBgCYivz5sKAmynuaS9vOPDgcRlVXl/spcTB2AJ/oRCCQggKIVT8pJ4pfeqNnKmG1u5aaLpc6ecXb2Q26/Yji3s2uZVRCEEhBIUQFEKIl1rp2XS5Ckwe395J0WS+ODw7l1JX1zZ7ldJ9qVMfXd1cvn8GhKLpy+Lr6VFKk1sZhRAUQlAIIR5GZyqzWQcmJ/PFyf2DN2qyty7fSoODbWKEhtaGe/HvLRaEunzLTv1vUAhBIQSFEPGfDa7+7svCG4VvcRixwo5FciujEIJCCAohkhP6CQAA///lDD1tMy8HCAAAAABJRU5ErkJggg=="
            }
        },
        {
            "name": "My test issuer",
            "locale": "en-US",
            "logo": {
                "uri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAIAAADYYG7QAAABD0lEQVR4nOyYsUrEQBRFVQYRYYUtZi0UC0vFUrBeYW1sF2E/wU623P8RkTSCf7FFipDaIkxhmkyapBgCYivz5sKAmynuaS9vOPDgcRlVXl/spcTB2AJ/oRCCQggKIVT8pJ4pfeqNnKmG1u5aaLpc6ecXb2Q26/Yji3s2uZVRCEEhBIUQFEKIl1rp2XS5Ckwe395J0WS+ODw7l1JX1zZ7ldJ9qVMfXd1cvn8GhKLpy+Lr6VFKk1sZhRAUQlAIIR5GZyqzWQcmJ/PFyf2DN2qyty7fSoODbWKEhtaGe/HvLRaEunzLTv1vUAhBIQSFEPGfDa7+7svCG4VvcRixwo5FciujEIJCCAohkhP6CQAA///lDD1tMy8HCAAAAABJRU5ErkJggg=="
            }
        }
    ],
    "credential_configurations_supported": {
        "university_example_sd_jwt": {
            "format": "vc+sd-jwt",
            "credential_signing_alg_values_supported": [
                "ES256"
            ],
            "cryptographic_binding_methods_supported": [
                "did:jwk"
            ],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [
                        "ES256"
                    ]
                }
            },
            "vct": "http://localhost:8080/vct/my-vct-v01",
            "claims": {
                "type": {
                    "mandatory": true,
                    "value_type": "string",
                    "display": [
                        {
                            "locale": "de-CH",
                            "name": "Abschluss Typ"
                        }
                    ]
                },
                "name": {
                    "mandatory": true,
                    "value_type": "string",
                    "display": [
                        {
                            "locale": "de-CH",
                            "name": "Diplomtitle"
                        }
                    ]
                },
                "average_grade": {
                    "mandatory": false,
                    "value_type": "number",
                    "display": [
                        {
                            "locale": "de-CH",
                            "name": "Notendurchschnitt"
                        }
                    ]
                }
            }
        }
    },
    "version": "1.0",
    "deferred_credential_endpoint": "http://localhost:8080/oid4vci/api/deferred_credential",
    "credential_endpoint": "http://localhost:8080/oid4vci/api/credential"
}
```

### Get access token for the credential offer

Actor: Wallet

The wallet decodes the `offer_deeplink` and extracts the `pre-authorized_code` value. The wallet then uses this code to
get a Bearer Token. The request body must be URL-encoded and the `grant_type` must be set
to `urn:ietf:params:oauth:grant-type:pre-authorized_code`.

```bash
curl -X 'POST' \
  'http://localhost:8080/oid4vci/api/token' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=THIS_IS_THE_PRE_AUTHORIZED_CODE_FROM_THE_OFFER_DEEPLINK'
```

With response:

```json
{
    "access_token": "your $ACCESS_TOKEN",
    "expires_in": 600,
    "c_nonce": "your $C_NONCE_V1",
    "token_type": "BEARER"
}
```

> [!NOTE]
> Please store the `access_token` as it is needed in later steps and will be referenced as `$ACCESS_TOKEN`.
> Also store the `c_nonce` ($C_NONCE_V1) as it is needed to create a holder proof.

## Deferred Credential Issuance V1

Actor: Wallet

> [!NOTE]
> The deferred credential request uses exactly the same endpoint and payload as the normal credential request. Only the
> response and following steps / calls are different.

To create the proof for the credential, you need the `$C_NONCE_V1` then build a JWT according to
the [SWISS-Profile-jwt-proof-type](https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#jwt-proof-type).
It is not recommended to reuse your private keys to sign different credentials.

```bash
curl -X 'POST' \
  'http://localhost:8080/oid4vci/api/credential' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer $ACCESS_TOKEN' \
  -d '{
    "format": "vc+sd-jwt",
    "proof": {
        "proof_type": "jwt",
        "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJUZXN0LUtleSIsIngiOiJtMDhWTkNBY1FSVGNBRVFrdlk5SUwzMHpXeG42Zk5UM2NTNVBvc0JqdGZ3IiwieSI6IjlkZUZKSVR0dWZkNGlwZXdOTEduMWVYRUpaSlBCR1AxTGtWV3dQZGloRnciLCJpYXQiOjE3NTQ2NDMzNjh9fQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkNHZjaSIsIm5vbmNlIjoiY2MxYmI4N2MtOTA3MC00OWE4LWFmMTYtNTA3MTkwZjg0ZmUyIiwiaWF0IjoxNzU0NjQzMzY4fQ.MFuxwr_TnEU6xqgaXkXaS0_6KRWSVd8LDPmkSUkMMrJlGHjL_m56B6TYiijZ_1HmpuS89hBSGT9xEsUbh-ShjA"
    }
}'
```

And the wallet receives a transaction ID in the response:

```json
{
    "transaction_id": "3c2e23f5-6aea-4478-b4a0-304fdc1b4933"
}
```

> [!NOTE]
> Please store the `transaction_id` as it is needed in later steps and will be referenced as `$TRANSACTION_ID`.
> Also store the `c_nonce` ($C_NONCE_V1) as it is needed to create a holder proof.

### With the transaction ID, the wallet can check if the credential is ready

Actor: Wallet

```bash
curl -X 'POST' \
  'http://localhost:8080/oid4vci/api/deferred_credential' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer $ACCESS_TOKEN' \
  -d '{ "transaction_id": "$TRANSACTION_ID"}'
```

And receives (as the business issuer has not evaluated the offer yet) the following response:

```json
{
    "error": "ISSUANCE_PENDING",
    "error_description": "The credential is not marked as ready to be issued"
}
```

### Business Issuer checks the offer updates status and sets the offer data (if desired)

Actor: Business Issuer

The business issuer can then either update the status of the offer (if the offer data is already set or not)

```bash
curl -X 'PATCH' 'http://localhost:8080/management/api/credentials/$MANAGEMENT_ID/status?credentialStatus=READY' -H 'accept: application/json'
```

Then receives:

```json
{
    "id": "$MANAGEMENT_ID",
    "status": "READY"
}
```

or can update the offer data which sets the status to READY automatically:

```bash
curl -X 'PATCH' \
  'http://localhost:8080/management/api/credentials/$MANAGEMENT_ID' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "Bachelor of Science",
    "name":"Data Science",
    "average_grade":"5.33"
  }'
```

Then receives:

```json
{
    "id": "$MANAGEMENT_ID",
    "status": "READY"
}
```

### With the transaction ID, the wallet can check if the credential is ready

Actor: Wallet

```bash
curl -X 'POST' \
  'http://localhost:8080/oid4vci/api/deferred_credential' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer $ACCESS_TOKEN' \
  -d '{ "transaction_id": "$TRANSACTION_ID"}'
```

And receives (as the business issuer has not evaluated the offer yet) the following response:

```json
{
    "credential": "eyJ2ZXIiOiIxLjAiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmxvY2FsaG9zdCUzQTgwODA6YWJjYWJjI3Nkand0In0.eyJfc2QiOlsiUF9fUEd0WVRLd0pwTDJRenZRY1pkU1BuLWUxamFtaEVOcGdhelNTS2ZZSSIsImRKUEFQWnFmbDA1ZjRzTE44VkpzV2NTSjFXdnNOeFAzd0YwQW9QeGNJSUEiLCJxM2lwVDJVa1RIbWNmMDlHMGx5MXlfWFlDYlVsbWd0Rm5hb0M5V3Y1c2J3Il0sInZjdCNpbnRlZ3JpdHkiOiJzaGEyNTYtU1ZITGZLZmNaY0JydytkOUVMLzFFWHh2R0Nka1E3dE1HdlptZDB5c01jaz0iLCJ2Y3QiOiJ0ZXN0IiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6dGR3OmV4YW1wbGUiLCJjbmYiOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsImtpZCI6IlRlc3QtS2V5IiwieCI6IlkzcFdCQnY0Tk5sMFN2bVk2WUdmbjc3Zjhid3d2cllsaVNiUkxVejk1TUEiLCJ5IjoiT01RdVE0SXZFTzNydUVya2ZqU0FKSk00NURhdy1SYXJTNy1tX0xHd2c5RSIsImlhdCI6MTc1NDY0NTI2NCwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJUZXN0LUtleSIsIngiOiJZM3BXQkJ2NE5ObDBTdm1ZNllHZm43N2Y4Ynd3dnJZbGlTYlJMVXo5NU1BIiwieSI6Ik9NUXVRNEl2RU8zcnVFcmtmalNBSkpNNDVEYXctUmFyUzctbV9MR3dnOUUiLCJpYXQiOjE3NTQ2NDUyNjR9fSwiaWF0IjoxNzU0NjQ1MjkzfQ.Yxz4ri2ztDdhp4jiOkenCp1_M1NKwGI_GX_lzLEj8CFQ0UppZtud5meTD1fC4K-1Oh82ii04fw08NhkVlTY87A~WyJwVW9kaUJmX2dmcnNzVFZCVHR5RHJnIiwibGFzdE5hbWUiLCJsYXN0TmFtZSJd~WyJIZmpPYW1YbEJqTDdqWU1ZMUpnZFFnIiwiZmlyc3ROYW1lIiwiZmlyc3ROYW1lIl0~WyJpa0xMS1pfV0IwdGxQMWhOUXdhZkhnIiwiZGF0ZU9mQmlydGgiLCIyMDAwLTAxLTAxIl0~",
    "format": "vc+sd-jwt"
}
```

## Deferred Credential Issuance V2

> [!WARNING]  
> Please be careful with V2. This part is still under construction and not yet pentested and should not be used in a
> production environment.

> [!NOTE]
> The deferred credential request uses exactly the same endpoint and payload as the normal credential request. Only the
> response and following steps / calls are different.

### Get Nonce

Actor: Wallet

```bash
curl -X 'POST' 'http://localhost:8080/oid4vci/api/nonce' -H 'accept: application/json'
```

With response:

```json
{
    "c_nonce": "c9c737f3-f37b-4331-a23c-313dc821fac5::2025-08-07T16:30:19.021045078Z"
}
```

> [!NOTE]
> Please store the `c_nonce` ($C_NONCE_V2) as it is needed to create a proof in the next step.

To create the proof for the credential, you need the `$C_NONCE_V2` then build a JWT according to
the [SWISS-Profile-jwt-proof-type](https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#jwt-proof-type).
It is not recommended to reuse your private keys to sign different credentials.

```bash
curl -X 'POST' \
  'http://localhost:8080/oid4vci/api/credential' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer $ACCESS_TOKEN' \
  -H 'SWIYU-API-Version: 2' \
  -d '{
    "credential_configuration_id": "university_example_sd_jwt",
    "proofs": {
        "jwt": [
          "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJUZXN0LUtleSIsIngiOiJtMDhWTkNBY1FSVGNBRVFrdlk5SUwzMHpXeG42Zk5UM2NTNVBvc0JqdGZ3IiwieSI6IjlkZUZKSVR0dWZkNGlwZXdOTEduMWVYRUpaSlBCR1AxTGtWV3dQZGloRnciLCJpYXQiOjE3NTQ2NDMzNjh9fQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkNHZjaSIsIm5vbmNlIjoiY2MxYmI4N2MtOTA3MC00OWE4LWFmMTYtNTA3MTkwZjg0ZmUyIiwiaWF0IjoxNzU0NjQzMzY4fQ.MFuxwr_TnEU6xqgaXkXaS0_6KRWSVd8LDPmkSUkMMrJlGHjL_m56B6TYiijZ_1HmpuS89hBSGT9xEsUbh-ShjA"
        ]
    }
}'
```

And the wallet receives a transaction ID in the response:

```json
{
    "transaction_id": "3c2e23f5-6aea-4478-b4a0-304fdc1b4933",
    "interval": 5
}
```

> [!NOTE]
> Please store the `transaction_id` as it is needed in later steps and will be referenced as `$TRANSACTION_ID`.

### Business Issuer checks the offer updates status and sets the offer data (if desired)

Actor: Business Issuer

The business issuer can then either update the status of the offer (if the offer data is already set or not)

```bash
curl -X 'PATCH' 'http://localhost:8080/management/api/credentials/$MANAGEMENT_ID/status?credentialStatus=READY' -H 'accept: application/json'
```

Then receives:

```json
{
    "id": "$MANAGEMENT_ID",
    "status": "READY"
}
```

or can update the offer data which sets the status to READY automatically:

```bash
curl -X 'PATCH' \
  'http://localhost:8080/management/api/credentials/$MANAGEMENT_ID' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "Bachelor of Science",
    "name":"Data Science",
    "average_grade":"5.33"
  }'
```

Then receives:

```json
{
    "id": "$MANAGEMENT_ID",
    "status": "READY"
}
```

### With the transaction ID, the wallet can check if the credential is ready

Actor: Wallet

```bash
curl -X 'POST' \git 
  'http://localhost:8080/oid4vci/api/deferred_credential' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer $ACCESS_TOKEN' \
  -H 'SWIYU-API-Version: 2' \
  -d '{ "transaction_id": "$TRANSACTION_ID"}'
```

And receives (as the business issuer has not evaluated the offer yet) the following response:

```json
{
    "credentials": [
        {
            "credential": "eyJ2ZXIiOiIxLjAiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmxvY2FsaG9zdCUzQTgwODA6YWJjYWJjI3Nkand0In0.eyJfc2QiOlsiTUpzN0FVY0QzU2VONzdCRFhPNldKN2xFTThDSjJ2dWxQU0J0WWpncUxRMCIsImdWVGdqazFzZmFQN1hXRjBmaWxlZEtuWG9KRkRJTEljZTJodmcwSDhiVG8iLCJtVUZjNmYwX290Y3dNTlJfb09JWF93dmNPUjRiQ2UtZHVmY0c5Vk9IblVzIl0sIm5iZiI6MTc1NDY0NjM0NCwidmN0IjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL29pZDR2Y2kvdmN0L215LXZjdC12MDEiLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDp0ZHc6ZXhhbXBsZSIsImNuZiI6eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2Iiwia2lkIjoiVGVzdC1LZXktMCIsIngiOiJOOUNsMjU3TEJfOWRGWGxJb0tzSUNjd0UwS2xOWGY1eDFiN0VuZlowbWlvIiwieSI6IlA5eU9SYXNtQUpNSU83WkZwTU1ROFZYaGRtaUFiSEQ4REllTExyTDR1Y3MiLCJpYXQiOjE3NTQ2NDYzNTQsImp3ayI6eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2Iiwia2lkIjoiVGVzdC1LZXktMCIsIngiOiJOOUNsMjU3TEJfOWRGWGxJb0tzSUNjd0UwS2xOWGY1eDFiN0VuZlowbWlvIiwieSI6IlA5eU9SYXNtQUpNSU83WkZwTU1ROFZYaGRtaUFiSEQ4REllTExyTDR1Y3MiLCJpYXQiOjE3NTQ2NDYzNTR9fSwiZXhwIjoxNzU0NjQ2NDc0LCJpYXQiOjE3NTQ2NDYzOTEsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJ0eXBlIjoiU3dpc3NUb2tlblN0YXR1c0xpc3QtMS4wIiwiaWR4IjowLCJ1cmkiOiJodHRwczovL2xvY2FsaG9zdDo4MDgwL3N0YXR1cyJ9fX0.wdxjKAhX1mcx6VcP1O0pOb-5CRZUQg_toqjaXd20tnwL8EH2-VN8Kj25t4rcYgOU2Gqt6J7tYSs-tOhg8FqgtA~WyJsM3lXQTg4dmR5REw2UWMxOEx2Q0xBIiwiYXZlcmFnZV9ncmFkZSIsIjUuMzMiXQ~WyJxaFQ1UDY5QWY5d2JJejVGWE1uLTFRIiwiZGVncmVlIiwiQmFjaGVsb3Igb2YgU2NpZW5jZSJd~WyIza09FaER1aTZsUmdIa2V3TUMtZDBnIiwibmFtZSIsIkRhdGEgU2NpZW5jZSJd~"
        }
    ]
}
```