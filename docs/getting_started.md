# Getting started with the SWIYU Generic Issuer (For integration use)

<div class="notice--danger">
  <h4 class="no_toc">Public Beta</h4>
  {{ notice-text | markdownify }}
</div>

The swiyu Generic Issuer is a web server implementing the technical standards as specified in
the ["Swiss Profile Issuance"](https://swiyu-admin-ch.github.io/specifications/swiss-profile-issuance/). Together with
the other generic components provided, this software forms a collection of APIs allowing issuance and verification of
verifiable credentials without the need of reimplementing the standards. You'll find additional documentation in
this [GitHub repository](https://github.com/swiyu-admin-ch/swiyu-issuer).

> [!IMPORTANT]
> Please be advised that the current system and its operations are provided on a best-effort basis and will continue to
> evolve over time. The security of the system and its overall maturity remain under development.

[![ecosystem components](https://swiyu-admin-ch.github.io/assets/images/components.png)](https://swiyu-admin-ch.github.io/assets/images/components.png)

# Deployment instructions

> [!IMPORTANT]
> Please make sure that you did the following steps before starting the deployment:
>
> - Registered yourself on the swiyu Trust Infrastructure portal
> - Registered yourself on the API self-service portal
> - Generated signing keys e.g. using the `didtoolbox.jar`
> - Generated a DID which is registered on the identifier registry
>
> The required steps are explained more thoroughly in
> the [Base- and Trust Registry Cookbook](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/)

## Set the environment variables

A sample compose file for an entire setup of both components and a database can be found in [
`sample.compose.yml`](https://github.com/swiyu-admin-ch/swiyu-issuer/blob/main/sample.compose.yml) file. You will need
to configure a list of environment variables in the `.env` file.

|---
| Name | Description | Example
| --- | --- |---
|`EXTERNAL_URL`| An URL which is used to build the correct deeplink (You must provide the /oid4vci and .well-known
endpoints at this) -> must use https-protocol and it must be reachable for the wallet otherwise the wallet will refuse
tp connect. | |
|`SPRING_APPLICATION_NAME`|Name of your application|
|`ISSUER_ID`|The DID you created in
the [onboarding process](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#create-a-did-or-create-the-did-log-you-need-to-continue)|
did:tdw:QmejrSkusQgeM6FfA23L6NPoLy3N8aaiV6X5Ysvb47WSj8:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:
ff8eb859-6996-4e51-a976-be1ca584c124 |
|`DID_STATUS_LIST_VERIFICATION_METHOD`|The Verification method, which can be taken from the did log response. The
Verification Method must match the selected
SIGNING_KEY! [onboarding process](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#create-a-did-or-create-the-did-log-you-need-to-continue)
|did:tdw:QmejrSkusQgeM6FfA23L6NPoLy3N8aaiV6X5Ysvb47WSj8:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:
ff8eb859-6996-4e51-a976-be1ca584c124#assert-key-01|
|`STATUS_LIST_KEY`|EC Private key can be taken
from [onboarding process](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#create-a-did-or-create-the-did-log-you-need-to-continue)
you can use any generated key but it must match the `DID_STATUS_LIST_VERIFICATION_METHOD`|
|`SWIYU_PARTNER_ID`|The partner id you created in
the [swiyu Trust Infrastructure business partner ID](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#business-partner-registration)
|d33fab52-1657-4240-9189-97c33b949739|
|`SWIYU_STATUS_REGISTRY_CUSTOMER_KEY`| Customer key
from [Status Registry API Key](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#get-api-keys-to-access-swiyu-apis)||
|`SWIYU_STATUS_REGISTRY_CUSTOMER_SECRET`| Customer Secret
from [Status Registry API Secret](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#get-api-keys-to-access-swiyu-apis)|
|`SWIYU_STATUS_REGISTRY_ACCESS_TOKEN`|Access token
from [Status Registry API ACCESS Token](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#get-api-keys-to-access-swiyu-apis)|
|`SWIYU_STATUS_REGISTRY_BOOTSTRAP_REFRESH_TOKEN`| Refresh token
from [Status Registry API Refresh Token](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#get-api-keys-to-access-swiyu-apis)|
|
`SWIYU_STATUS_REGISTRY_TOKEN_URL`|[OAuth Refresh URL](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#authenticate-with-oauth2)|https://keymanager-prd.api.admin.ch/keycloak/realms/APIGW/protocol/openid-connect|
|
`SWIYU_STATUS_REGISTRPY_API_URL`|[Status Registry Base URL](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#base-urls)|https://status-reg-api.trust-infra.swiyu-int.admin.ch|
|`DID_SDJWT_VERIFICATION_METHOD`| Verification method, which can be taken from the did log response. The Verification
Method must match the selected SIGNING_KEY! | did:tdw:QmejrSkusQgeM6FfA23L6NPoLy3N8aaiV6X5Ysvb47WSj8:
identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:ff8eb859-6996-4e51-a976-be1ca584c124#assert-key-02 |
|`SDJWT_KEY`| EC Private key can be taken
from [onboarding process](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/#create-a-did-or-create-the-did-log-you-need-to-continue)
you can use any generated key but it must match the `DID_SDJWT_VERIFICATION_METHOD` | |

Please note that in the default configuration the issuer service is set up in a way to easily gain experience with the
verification process, not intended for production use. For additional information on how to securely deploy the
swiyu-issuer check out
the [Deployment considerations](https://github.com/swiyu-admin-ch/swiyu-issuer/blob/main/README.md#deployment-considerations)
in the readme.

The provided images can be used with arm based processors, but they are not optimized.

The latest image is available here:

- [swiyu-issuer](https://github.com/swiyu-admin-ch/swiyu-issuer/releases)

Once the service is deployed you can create your first verifiable credential (vc).

## Creating a verifiable credential

> [!TIP]
> For a detailed understanding of the issuance process please consult the [Issuance Process](issuance.md) or
> the [documentation](https://github.com/swiyu-admin-ch/swiyu-issuer/blob/main/docs/Architecture_generic_issuer.pdf).

Below you find an example for with the interactions needed with the issuer to issue a verifiable credential. The
following request can be performed by using the [swagger endpoint](http://localhost:8080/swagger-ui/index.html) for the
sample environment.

**Request**

> [!WARNING]
> The example below is only a bare minimum working example.

### 1. Create status list entry

First, you need to create a status list

```bash
curl -X 'POST' \
  'http://localhost:8080/management/api/status-list' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
  "type": "string",
  "maxLength": 100000,
  "config": {
    "bits": 2
  }
}'
```

With response:

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

> [!IMPORTANT]
> It's recommended to store the value of `"statusRegistryUrl"` response field, as it is needed in later steps and will
> be referenced as `${STATUS_REGISTRY_URL}`.

More details about the status list creation can be found [here](issuance.md#create-status-list-entry).

### 2. Create an initial vc offer

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

With response:

The request above should produce the following response (the placeholders `${CREDENTIAL_ID}` and
`${SWIYU_OFFER_DEEPLINK}` denote concrete values):

```json
{
    "management_id": "${CREDENTIAL_ID}",
    "offer_deeplink": "${SWIYU_OFFER_DEEPLINK}"
}
```

## Update status

You can set the following status: `CANCELLED`, `READY`, `ISSUED`, `SUSPENDED`, `REVOKED`. For additional details about
the status check
the [documentation](https://github.com/swiyu-admin-ch/swiyu-issuer?tab=readme-ov-file#credential-status).
Using the Issuer Management service the status can be updated

<div class="notice--warning">
  ⚙️ Please, ensure the shell variable <code>CREDENTIAL_ID</code> has already been set accordingly (see above).
</div>

```bash
curl -X 'PATCH' http://localhost:8080/management/api/credentials/${CREDENTIAL_ID}/status?credentialStatus=CANCELLED
```

The response then looks like:

```json
{
    "id": "${CREDENTIAL_ID}",
    "status": "CANCELLED"
}
```

# Development instructions

Instructions for the development of the swiyu Generic Issuer can be found in
the [GitHub repository](https://github.com/swiyu-admin-ch/swiyu-issuer?tab=readme-ov-file#development).

## Create Images for ARM based processors

In order to optimize the image for arm based systems, you first have to check out
the [repository](https://github.com/swiyu-admin-ch/swiyu-issuer).

To create an image you to run the following command in the repository to create a local images of the service:

```bash
./mvnw install:install-file -Dfile=lib/primusX-java11-2.4.4.jar -DgroupId=com.securosys.primus -DartifactId=jce -Dversion=2.4.4 -Dpackaging=jar spring-boot:build-image
```

# Testing your instance

We provide a [test application](https://github.com/swiyu-admin-ch/swiyu-generic-application-test) for running end-to-end
tests and a [test wallet](https://github.com/swiyu-admin-ch/swiyu-generic-test-wallet) to validate your instance of the
generic components.

# Your Feedback?

We would be pleased if you spend about 3 additional minutes and give us feedback on the swiyu Public Beta Trust
Infrastructure and your onboarding process! With Public Beta, we want to give ecosystem stakeholders the opportunity to
gain initial experience and build their own use cases on the trust infrastructure of the future e-ID.
Your [feedback](https://findmind.ch/c/feedback_publicbeta_infr_en) will help us to further develop and improve the
touchpoints, and we greatly appreciate your support.
