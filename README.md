# Generic Issuer management service

## Setup

- Start application IssuerManagementApplication with local profile
  - Starts docker compose for database
  - Runs Flyway migrations if needed
- Api definitions can be found [here](http://localhost:8080/swagger-ui/index.html#/)


## Configuration
The Generic Issuer Agent Management is configured using environment variables.


### JWT Based Authentication
If there is the need to further protect the API it is possible to enable the feature with a flag and
set the environment variables with the allowed public key as a JSON Web Key Set


    ENABLE_JWT_AUTH=true
    JWKS_ALLOWLIST={"keys":[{"kty":"EC","crv":"P-256","kid":"testkey","x":"_gHQsZT-CB_KvIfpvJsDxVSXkuwRJsuof-oMihcupQU","y":"71y_zEPAglUXBghaBxypTAzlNx57KNY9lv8LTbPkmZA"}]}

If the JWT based authentication is activated it's expected to all in calls be wrapped in a signed JWT with the claim "data".
The value of the data claim will contain the full json body of the normal request.  

Note that this is only affects writing calls.