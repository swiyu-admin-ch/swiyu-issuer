/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("testjwt")
@AutoConfigureMockMvc
class CredentialOfferCreateJwtIT {

    private static final String BASE_URL = "/management/api/v1/credentials";

    @Autowired
    private MockMvc mvc;

    /**
     * Create an offer with Issuer Agent Management configured to require the
     * request
     * being a JWT with the signature matching one of the entries in the whitelist
     * of the config
     */
    @Test
    void createOfferWithJWT() throws Exception {
        // This offerData is the data we want to offer in the Verifiable Credential
        String offerData = """
                {
                    "lastName": "Example",
                    "firstName": "Edward",
                    "dateOfBirth": "1.1.1970"
                  }""";
        // We add the data to the other parts needed for offering a credential
        String jsonPayload = String.format("""
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": %s,
                  "offer_validity_seconds": 36000
                }
                """, offerData);
        var resp = testJWTCreateOffer(jsonPayload);

        ObjectMapper mapper = new ObjectMapper();
        assert mapper.readTree(resp.getResponse().getContentAsString()).equals(mapper.readTree(offerData));
    }

    /**
     * Create an offer with Issuer Agent Management configured to require the
     * request.
     * Issuer Agent OID4VCI is also configured to require data integrity checking
     * the signature with another whitelist configured there.
     */
    @Test
    void createOfferWithJWTAndInnerJWT() throws Exception {
        // Offer data we want to use in the VC as JWT
        String offerData = "eyJraWQiOiJ0ZXN0a2V5IiwiYWxnIjoiRVMyNTYifQ.eyJkYXRhIjoie1xuICBcIm1ldGFkYXRhX2NyZWRlbnRpYWxfc3VwcG9ydGVkX2lkXCI6IFtcInRlc3RcIl0sXG4gIFwiY3JlZGVudGlhbF9zdWJqZWN0X2RhdGFcIjogXCJleUpoYkdjaU9pSklVekkxTmlJc0luUjVjQ0k2SWtwWFZDSjkuZXlKc1lYTjBUbUZ0WlNJNklrVjRZVzF3YkdVaUxDSm1hWEp6ZEU1aGJXVWlPaUpGWkhkaGNtUWlMQ0prWVhSbFQyWkNhWEowYUNJNklqRXVNUzR4T1Rjd0luMC4yVk1qajFScEo3alVqbjFTSkhEd3d6cXgza3lnbjg4VXhTc0c1ajF1WEc4XCIsXG4gIFwib2ZmZXJfdmFsaWRpdHlfc2Vjb25kc1wiOiAzNjAwMFxufVxuIn0.Cf8abrwYa9aK8V0XYblrW5HoeVX-dz_AdvF3f7rgCW4FvEKFc4i2jZpx3O7lS5Vn6a4AmXPyRm-IaHrPxqJgNQ";
        // Adding in the offer data is done in the same way as without data integrity
        String jsonPayload = String.format("""
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": "%s",
                  "offer_validity_seconds": 36000
                }
                """, offerData);
        var resp = testJWTCreateOffer(jsonPayload);
        assert resp.getResponse().getContentAsString().equals(offerData);
    }

    @Test
    void createOfferWithJWTAndInnerJWTInvalidKey_thenBadRequest() throws Exception {
        // Offer data we want to use in the VC as JWT
        String offerData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsYXN0TmFtZSI6IkV4YW1wbGUiLCJmaXJzdE5hbWUiOiJFZHdhcmQiLCJkYXRlT2ZCaXJ0aCI6IjEuMS4xOTcwIn0.2VMjj1RpJ7jUjn1SJHDwwzqx3kygn88UxSsG5j1uXG8";

        // Adding in the offer data is done in the same way as without data integrity
        String jsonPayload = String.format("""
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": "%s",
                  "offer_validity_seconds": 36000
                }
                """, offerData);
        createOfferMvcResult(jsonPayload)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Data Integrity of offer could not be verified. No matching key found"));
    }

    @Test
    void createOfferMissingJwt_thenBadRequest() throws Exception {
        // This offerData is the data we want to offer in the Verifiable Credential
        String offerData = """
                {
                    "lastName": "Example",
                    "firstName": "Edward",
                    "dateOfBirth": "1.1.1970"
                  }""";
        // We add the data to the other parts needed for offering a credential
        String jsonPayload = String.format("""
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": %s,
                  "offer_validity_seconds": 36000
                }
                """, offerData);

        mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isUnauthorized());
    }

    private MvcResult testJWTCreateOffer(String jsonPayload) throws Exception {
        MvcResult result = createOfferMvcResult(jsonPayload)
                .andExpect(status().isOk())
                .andReturn();

        String id = JsonPath.read(result.getResponse().getContentAsString(), "$.management_id");

        return mvc.perform(get(String.format("%s/%s", BASE_URL, id)))
                .andExpect(status().isOk())
                .andReturn();
    }

    private ResultActions createOfferMvcResult(String jsonPayload) throws Exception {
        ECKey ecJWK = ECKey.parse(ApplicationIT.privateKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("data", jsonPayload).build();

        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("testkey").build(), claims);
        jwt.sign(new ECDSASigner(ecJWK));
        String payload = jwt.serialize();
        return mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload));
    }
}