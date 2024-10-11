# Generic Issuer management service

This software is a web server implementing the technical standards as specified in
the [Swiss E-ID & Trust Infrastructure technical roadmap](https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/tech-roadmap.md).
Together with the other generic components provided, this software forms a collection of APIs allowing issuance and
verification of verifiable credentials without the need of reimplementing the standards.

The Generic Issuer Management Service is the interface to offer a credential. It should be only accessible from the
issuers internal organization.

As with all the generic issuance & verification services it is expected that every issuer and verifier hosts their own
instance of the service.

The issuer management service is linked to the issuer signer services through a database, allowing to scale the signer
service independently from the management service.

```mermaid
flowchart TD
    issint[\Issuer Business System\]
    isam(Issuer Management Service)
    isdb[(Postgres)]
    isoi(Issuer Signer Service)
    wallet[Wallet]
    issint ---> isam
    isam ---> isdb
    isoi ---> isdb
    wallet ---> isoi
```

# Development

## Setup

- Start application IssuerManagementApplication with local profile
    - Starts docker compose for database
    - Runs Flyway migrations if needed

- Api definitions can be found [here](http://localhost:8080/swagger-ui/index.html#/)

## Configuration

### Generate Keys

Currently only EC 256 keys are used.
Generate private key with:
`openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem`
Remember to keep private keys private and safe. It should never be transmitted, etc.

On the base registry the public key is published. To generate the public key form the private key we can use
`openssl ec -in private.pem -pubout -out ec_public.pem`

### Configuration Environment Variables

The Generic Issuer Agent Management is configured using environment variables.

| Variable                            | Description                                                                                                                                             |
|-------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| POSTGRES_USER                       | Username to connect to the Issuer Agent Database shared with the issuer agent managment service                                                         |
| POSTGRES_PASSWORD                   | Username to connect to the Issuer Agent Database                                                                                                        |
| POSTGRES_JDBC                       | JDBC Connection string to the shared DB                                                                                                                 |
| EXTERNAL_URL                        | The URL of the Issuer Signer. This URL is used in the credential offer link sent to the Wallet                                                          |
| ENABLE_JWT_AUTH                     | Enables the requirement of writing calls to the issuer management to be signed JWT                                                                      |
| JWKS_ALLOWLIST                      | A Json Web Key set of the public keys authorized to do writing calls to the issuer management service                                                   |  
| CONTROLLER_URL                      | URL of the registry controller used                                                                                                                     |
| STATUS_LIST_KEY                     | Private Signing Key for the status list vc, the matching public key should be published on the base registry                                            |
| DID_STATUS_LIST_VERIFICATION_METHOD | Verification Method (id of the public key as in did doc) of the public part of the status list signing key. Contains the whole did:tdw:....#keyFragment |

### Kubernetes Vault Keys

| Variable                   | Description                                                                                                  |
|----------------------------|--------------------------------------------------------------------------------------------------------------|
| secret.db.username         | Username to connect to the Issuer Agent Database shared with the issuer agent managment service              |
| secret.db.password         | Username to connect to the Issuer Agent Database                                                             |
| secret.key.status-list.key | Private Signing Key for the status list vc, the matching public key should be published on the base registry |

## Data Structure

```mermaid
erDiagram
    CREDENTIAL_OFFER {
        uuid id PK
        text credential_status
        text metadata_credential_supported_id
        jsonb offer_data
        uuid holder_binding_nonce
        uuid access_token
        integer offer_expiration_timestamp
        text credential_valid_from
        text credential_valid_until
    }

    CREDENTIAL_OFFER_STATUS {
        uuid credential_offer_id PK, FK
        uuid status_id PK, FK
        integer index
    }

    STATUS_LIST {
        uuid id PK
        text type
        jsonb config
        text uri
        text status_zipped
        int last_used_index
        int max_length
    }

    CREDENTIAL_OFFER one to many CREDENTIAL_OFFER_STATUS: "has status"
    STATUS_LIST one to many CREDENTIAL_OFFER_STATUS: "is referenced in"
```

Note: Status List info comes from config and are populated to the DB the first time a Credential uses the status.
ID of the credential offer is also the id used by the issuer adapter (the component communicating with the issuer agent
management) to revoke the credential. It is returned when a new offer is created. It's recommended to save this id to
revoke the credential later on.

### JWT Based Authentication

If there is the need to further protect the API it is possible to enable the feature with a flag and
set the environment variables with the allowed public key as a JSON Web Key Set

    ENABLE_JWT_AUTH=true
    JWKS_ALLOWLIST={"keys":[{"kty":"EC","crv":"P-256","kid":"testkey","x":"_gHQsZT-CB_KvIfpvJsDxVSXkuwRJsuof-oMihcupQU","y":"71y_zEPAglUXBghaBxypTAzlNx57KNY9lv8LTbPkmZA"}]}

If the JWT based authentication is activated it's expected to all in calls be wrapped in a signed JWT with the claim "
data".
The value of the data claim will contain the full json body of the normal request.

Note that this is only affects writing calls.

### Data Integrity Check
To provide a data integrity check with the issuer it is possible to provide the credential subject data as JWT.

See [CredentialOfferCreateJWTIT.java](src/test/java/ch/admin/bit/eid/issuer_management/it/CredentialOfferCreateJWTIT.java) for examples on how to use.

## Credential Status

```mermaid
stateDiagram-v2
    OFFERED
    IN_PROGRESS
    EXPIRED
    ISSUED
    SUSPENDED
    REVOKED
    [*] --> OFFERED
    IN_PROGRESS --> OFFERED: reset
    IN_PROGRESS --> ISSUED: issue credential (delete vc data)
    IN_PROGRESS --> EXPIRED: validity posix timestamp exceeded
    OFFERED --> REVOKED: revoke offer
    OFFERED --> IN_PROGRESS: Redeem token
    OFFERED --> EXPIRED: validity posix timestamp exceeded
    ISSUED --> SUSPENDED: suspend
    SUSPENDED --> ISSUED: unsuspend
    ISSUED --> REVOKED: revoke
    SUSPENDED --> REVOKED: revoke
```

## Contribution

We appreciate feedback and contribution. More information can be found in the [CONTRIBUTING-File](/CONTRIBUTING.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.
