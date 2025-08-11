# Credential Issuance documentation

## Prerequisites for all calls (V1 and V2)

```mermaid
sequenceDiagram
    actor BUSINESS as Business Issuer 

    participant ISS as Issuer Agent
    participant DB as Issuer DB
    participant STATUS as Status Registry

    actor WALLET as Holder

    # Create offer
    BUSINESS->>+ISS: Create offer
    ISS->>+STATUS: Create status list entry
    STATUS->>-ISS: 
    ISS->>+DB : Store offer
    DB-->>-ISS : 
    ISS-->>-BUSINESS : Return offer details (incl. deeplink)

    # Pass deeplink to WALLET
    BUSINESS-->>+WALLET : Pass deeplink to wallet
    Note over BUSINESS,WALLET: INFO: Passing the deeplink to the wallet is not part of this service and must be handled by the Business Issuer

    loop Status check
        BUSINESS->>+ISS: Get status
        ISS-->>-BUSINESS : 
    end

    # Get credential
    WALLET->>+ISS : Get openid metadata
    ISS-->>-WALLET : 

    WALLET->>+ISS : Get issuer metadata
    ISS-->>-WALLET : 
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
    "nextFreeIndex": 0,
    "version": "1.0",
    "config": {
        "bits": 2
    }
}
```

### Create credential offer

> [!NOTE]
> If `"credential_metadata": { "vct#integrity": "sha256-0000000000000000000000000000000000000000000=" }, vct#integrity`
> is set then the `vct#integrity` claim is added to the final credential.

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
  "offer_validity_seconds": 86400,
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
            "RSA-OAEP-256",
            "ECDH-ES+A128KW"
        ],
        "enc_values_supported": [
            "A128CBC-HS256"
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

## Credential Issuance V1

Here you can find the different calls and responses for the credential issuance process. The sequence diagram above
illustrates the flow of messages between the Business Issuer, Issuer Agent, Issuer Database, Status Registry, and
Wallet.

This is currently the default flow for credential issuance. The v2 flow is currently in development and should not be
used in production.

```mermaid
sequenceDiagram
    actor WALLET as Holder

    participant ISS as Issuer Agent
    participant DB as Issuer DB

    # Get credential
    WALLET->>+ISS : Get openid metadata
    ISS-->>-WALLET : 

    WALLET->>+ISS : Get issuer metadata
    ISS-->>-WALLET : 

    WALLET->>+ISS : Get oauth token
    ISS-->>-WALLET : Oauth token

     
    WALLET->>+ISS: Get credential
    ISS->>+DB : Get offer data and status list INFO
    DB-->>-ISS : 
    ISS-->>-WALLET : VC

```

### Get credential

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
        "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJUZXN0LUtleSIsIngiOiJmeUx4T1ZaSmpOdnVud1EyXy1ncmcxalZwSWM1ZFhIR3BwUlQ1UXVVV0k0IiwieSI6ImxYMXZLRTl5dEF0MkZTazRKV2NwcW9UbzQ5bW52MGpva0NoMUZXdWEyamsiLCJpYXQiOjE3NTQ1ODEzODh9fQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkNHZjaSIsIm5vbmNlIjoiNWFkYWJlNjYtNmM1OC00NjEyLThiYjMtYjAzNDJlZWZhY2JjIiwiaWF0IjoxNzU0NTgxMzg4fQ.YKR2v4K7joiJvow5KurTxt7pP5lsx3nvWzDONIp2VTtluddT_jOADTJYDA-PKVjoA_c2exqDa8RUPK6roYjnnw"
    }
}'
```

And the wallet receives the credential in the response:

```json
{
    "credential": "eyJ2ZXIiOiIxLjAiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmxvY2FsaG9zdCUzQTgwODA6YWJjYWJjI3Nkand0In0.eyJfc2QiOlsiMkVHOG55NjVPY1RjMDYxSGtUbW43M0NJV3hHT2xFVVpMbUkxc3B2NVNmMCIsInNKNXNaZ2wyU1VIU18zOGJwOXJYMnpHQ0hjcHlXQ0EtcUpOaE1UWlZvXzgiLCJ6bW5HRUdTd3NWdlNhVFpPZ18zR0Q1WHIybzdwS2FzRnF6WkxtRGQzT2lvIl0sInZjdCNpbnRlZ3JpdHkiOiJzaGEyNTYtU1ZITGZLZmNaY0JydytkOUVMLzFFWHh2R0Nka1E3dE1HdlptZDB5c01jaz0iLCJuYmYiOjE3NTQ1ODEzNzgsInZjdCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9vaWQ0dmNpL3ZjdC9teS12Y3QtdjAxIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6dGR3OmV4YW1wbGUiLCJjbmYiOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsImtpZCI6IlRlc3QtS2V5IiwieCI6ImZ5THhPVlpKak52dW53UTJfLWdyZzFqVnBJYzVkWEhHcHBSVDVRdVVXSTQiLCJ5IjoibFgxdktFOXl0QXQyRlNrNEpXY3Bxb1RvNDltbnYwam9rQ2gxRld1YTJqayIsImlhdCI6MTc1NDU4MTM4OCwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJUZXN0LUtleSIsIngiOiJmeUx4T1ZaSmpOdnVud1EyXy1ncmcxalZwSWM1ZFhIR3BwUlQ1UXVVV0k0IiwieSI6ImxYMXZLRTl5dEF0MkZTazRKV2NwcW9UbzQ5bW52MGpva0NoMUZXdWEyamsiLCJpYXQiOjE3NTQ1ODEzODh9fSwiZXhwIjoxNzU0NTgxNTA4LCJpYXQiOjE3NTQ1ODE0MTIsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJ0eXBlIjoiU3dpc3NUb2tlblN0YXR1c0xpc3QtMS4wIiwidXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODA4MC9zdGF0dXMiLCJpZHgiOjB9fX0.iTC8TZEJAOoE4DuWBtNSsSsy3dhaVmzXhql6k_K0pCVJszMBnEc0vbTszZYcjfwB2svriZGXBAiGZzgZZJ6Psg~WyJTYXRZVGQ2X1UwZWJ2NkZIWXJpQ1Z3IiwiYXZlcmFnZV9ncmFkZSIsIjUuMzMiXQ~WyJTb3dTSk1PVWdZMm5qSnlNZnRGdER3IiwiZGVncmVlIiwiQmFjaGVsb3Igb2YgU2NpZW5jZSJd~WyJCa3YwZ3BiTnFwYVA5TzZRay04VVZnIiwibmFtZSIsIkRhdGEgU2NpZW5jZSJd~",
    "format": "vc+sd-jwt"
}
``` 

## Credential Issuance V2

> [!WARNING]  
> Please be careful with V2. This part is still under construction and not yet pentested and should not be used in a
> production environment.

```mermaid
sequenceDiagram
    actor WALLET as Holder
    participant ISS as Issuer Agent
    participant DB as Issuer DB

    # Get credential
    WALLET->>+ISS : Get openid metadata
    ISS-->>-WALLET : 

    WALLET->>+ISS : Get issuer metadata
    ISS-->>-WALLET : 

    WALLET->>+ISS : Get oauth token
    ISS-->>-WALLET : Oauth token

    WALLET->>+ISS : Get Nonce
    ISS->>+DB : Store Nonce
    DB-->>-ISS : 
    ISS-->>-WALLET : 

    WALLET->>+ISS: Get credential
    ISS->>+DB : Get offer data and status list INFO
    DB-->>-ISS : 
    ISS->>+DB : Get Nonce
    DB-->>-ISS :
    ISS->>ISS : Check Nonce
    ISS->>+DB : Invalidate Nonce
    ISS-->>-WALLET : VC
```

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

### Request credential

To create the proof for the credential, you need the `$C_NONCE_V2` then build a JWT according to
the [SWISS-Profile-jwt-proof-type](https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#jwt-proof-type).
It is not recommended to reuse your private keys to sign different credentials.

```bash
curl -X 'POST' \
  'http://localhost:8080/oid4vci/api/credential' \
  -H 'accept: application/json' \
  -H 'SWIYU-API-Version: 2' \
  -H 'Authorization: Bearer $ACCESS_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "credential_configuration_id": "university_example_sd_jwt",
    "proofs": {
        "jwt": [
            "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJUZXN0LUtleS0wIiwieCI6Ii1QRXVmRjdnZmRta0dHVGQ5cG95YkdqdmkzSUxpeWFSdDNHN0F5aWxOSmsiLCJ5IjoianMyRDNHRzNsdEZEZGplbG1yYzVWby0tejFoTnJJT3VVdFFtTGs1RkozTSIsImlhdCI6MTc1NDU4NDE3OH19.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkNHZjaSIsIm5vbmNlIjoiYzljNzM3ZjMtZjM3Yi00MzMxLWEyM2MtMzEzZGM4MjFmYWM1OjoyMDI1LTA4LTA3VDE2OjMwOjE5LjAyMTA0NTA3OFoiLCJpYXQiOjE3NTQ1ODQzMTl9.tq_ZvRbz7BoGOdMrPHwSw64gI-wzqQ7sD4XfjdKIW3iL8rj7FX-s8Fpsed0C8qITUl3K_8UWRfeoLZwA85NKuA"
        ]
    }
}'
```