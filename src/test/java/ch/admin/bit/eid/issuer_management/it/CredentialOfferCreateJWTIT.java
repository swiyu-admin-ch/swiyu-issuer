package ch.admin.bit.eid.issuer_management.it;

import ch.admin.bit.eid.issuer_management.IssuerManagementApplicationTests;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("testjwt")
@AutoConfigureMockMvc
class CredentialOfferCreateJWTIT {
    @Autowired
    private MockMvc mvc;

    protected static final String BASE_URL = "/credentials";

    @Test
    void createOfferWithJWT() throws Exception {
        String offerData = "{\"hello\":\"world\"}";
        String jsonPayload = """
                        {
                          "metadata_credential_supported_id": "test",
                          "credential_subject_data": {
                            "hello": "world"
                          },
                          "offer_validity_seconds": 36000
                        }
                        """;
        testJWTCreateOffer(jsonPayload, offerData);
    }

    @Test
    void createOfferWithJWTAndInnerJWT() throws Exception {
        String offerData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.eH9qoMvdv12LsZ3Og_K20no8uiBQFuJg6k6A7O8l06U";
        String jsonPayload = String.format("""
                {
                  "metadata_credential_supported_id": "test",
                  "credential_subject_data": %s,
                  "offer_validity_seconds": 36000
                }
                """, offerData);
        testJWTCreateOffer(jsonPayload, offerData);
    }

    private void testJWTCreateOffer(String jsonPayload, String offerData) throws Exception {
        ECKey ecJWK = ECKey.parse(IssuerManagementApplicationTests.privateKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("data", jsonPayload).build();

        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("testkey").build(), claims);
        jwt.sign(new ECDSASigner(ecJWK));
        String payload = jwt.serialize();
        MvcResult result = mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();

        String id = JsonPath.read(result.getResponse().getContentAsString(), "$.management_id");

        mvc.perform(get(String.format("%s/%s", BASE_URL, id)))
                .andExpect(status().isOk())
                .andExpect(content().string(offerData));
    }
}
