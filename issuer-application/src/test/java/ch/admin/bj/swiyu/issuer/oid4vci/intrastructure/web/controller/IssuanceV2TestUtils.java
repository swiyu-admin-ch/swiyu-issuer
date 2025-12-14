package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
import ch.admin.bj.swiyu.issuer.util.DemonstratingProofOfPossessionTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;
import org.mockito.Mock;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@UtilityClass
public class IssuanceV2TestUtils {

    public static ResultActions requestCredentialV2(MockMvc mock, String token, String credentialRequestString) throws Exception {
        return mock.perform(post("/oid4vci/api/credential")
                .header("Authorization", String.format("BEARER %s", token))
                .header("SWIYU-API-Version", "2")
                .content(credentialRequestString)
        );
    }

    public static ResultActions requestCredentialV2WithDpop(MockMvc mock, String token, String credentialRequestString, IssuerMetadata issuerMetadata, ECKey dpopKey) throws Exception {
        return mock.perform(post("/oid4vci/api/credential")
                .header("Authorization", String.format("BEARER %s", token))
                .header("SWIYU-API-Version", "2")
                .header("DPoP", createDpop(
                        mock,
                        issuerMetadata.getNonceEndpoint(),
                        "POST",
                        issuerMetadata.getCredentialEndpoint(),
                        token,
                        dpopKey
                ))
                .content(credentialRequestString)
        );
    }

    public static JsonArray extractCredentialsV2(MvcResult response) throws UnsupportedEncodingException {
        var responseJson = JsonParser.parseString(response.getResponse().getContentAsString()).getAsJsonObject();

        return responseJson.get("credentials").getAsJsonArray();
    }

    public void testHolderBindingV2(String vc, ECKey holderPrivateKey) throws ParseException {
        JsonObject claims = getVcClaims(vc);
        assertNotNull(claims.get("cnf"));
        JsonObject legacyCnf = claims.get("cnf").getAsJsonObject();
        JsonObject cnf = legacyCnf.get("jwk").getAsJsonObject();

        // for legacy reasons the cnf is not a JWK but a map with the same properties
        assertEquals(holderPrivateKey.getKeyID(), legacyCnf.get("kid").getAsString());
        assertEquals(holderPrivateKey.getCurve().toString(), legacyCnf.get("crv").getAsString());
        assertEquals(holderPrivateKey.getX().toString(), legacyCnf.get("x").getAsString());
        assertEquals(holderPrivateKey.getY().toString(), legacyCnf.get("y").getAsString());

        assertNotNull(cnf);
        assertEquals(holderPrivateKey.getKeyID(), cnf.get("kid").getAsString());
        assertEquals(holderPrivateKey.getCurve().toString(), cnf.get("crv").getAsString());
        assertEquals(holderPrivateKey.getX().toString(), cnf.get("x").getAsString());
        assertEquals(holderPrivateKey.getY().toString(), cnf.get("y").getAsString());
    }

    public static JsonObject getVcClaims(String vc) throws ParseException {
        var jwt = SignedJWT.parse(vc.split("~")[0]);
        return JsonParser.parseString(jwt.getPayload().toString()).getAsJsonObject();
    }

    public static String getCredentialRequestStringV2(MockMvc mock, List<ECKey> holderPrivateKeys, ApplicationProperties applicationProperties, String encryption) throws Exception {

        var nonceResponse = mock.perform(post("/oid4vci/api/nonce")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        JsonObject nonceResponseJson = JsonParser.parseString(nonceResponse).getAsJsonObject();
        String nonce = nonceResponseJson.get("c_nonce").getAsString();

        List<String> proofs = new ArrayList<>(holderPrivateKeys.size());
        for (ECKey holderPrivateKey : holderPrivateKeys) {
            String proof = TestServiceUtils.createHolderProof(holderPrivateKey, applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    false);
            proofs.add(proof);
        }
        var proofString = proofs.stream().reduce((a, b) -> a + "\", \"" + b).orElse("");
        if (encryption == null) {
            return String.format("{\"credential_configuration_id\": \"%s\", \"proofs\": {\"jwt\": [\"%s\"]}}",
                    "university_example_sd_jwt", proofString);
        } else {
            return String.format("{\"credential_configuration_id\": \"%s\", \"credential_response_encryption\": %s, \"proofs\": {\"jwt\": [\"%s\"]}}", "university_example_sd_jwt", encryption, proofString);
        }
    }

    public static String getCredentialRequestStringV2(MockMvc mock, List<ECKey> holderPrivateKeys, ApplicationProperties applicationProperties) throws Exception {
        return getCredentialRequestStringV2(mock, holderPrivateKeys, applicationProperties, null);
    }

    public static List<ECKey> createHolderPrivateKeysV2(int numberOfKeys) throws JOSEException {
        List<ECKey> holderPrivateKeys = new ArrayList<>(numberOfKeys);
        for (int i = 0; i < numberOfKeys; i++) {
            holderPrivateKeys.add(createPrivateKeyV2("Test-Key-" + i));
        }
        return holderPrivateKeys;
    }

    public static ECKey createPrivateKeyV2(String keyName) throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(keyName)
                .issueTime(new Date())
                .generate();
    }

    public static String getAccessTokenFromDeeplink(MockMvc mock, String deeplink) throws Exception {
        var decodedDeeplink = URLDecoder.decode(deeplink, StandardCharsets.UTF_8);
        var credentialOfferString = decodedDeeplink.replace("swiyu://?credential_offer=", "");

        var credentialOffer = JsonParser.parseString(credentialOfferString).getAsJsonObject();
        var grants = credentialOffer.get("grants").getAsJsonObject();
        var preAuthorizedCode = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code").getAsJsonObject()
                .get("pre-authorized_code").getAsString();

        var tokenResponse = mock.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                        .param("pre-authorized_code", preAuthorizedCode))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return JsonParser.parseString(tokenResponse)
                .getAsJsonObject()
                .get("access_token")
                .getAsString();
    }

    public String getPreAuthCodeFromDeeplink(String deeplink) throws Exception {
        var decodedDeeplink = URLDecoder.decode(deeplink, StandardCharsets.UTF_8);
        var credentialOfferString = decodedDeeplink.replace("swiyu://?credential_offer=", "");

        var credentialOffer = JsonParser.parseString(credentialOfferString).getAsJsonObject();
        var grants = credentialOffer.get("grants").getAsJsonObject();
        return grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code").getAsJsonObject()
                .get("pre-authorized_code").getAsString();
    }


    public static String createDpop(MockMvc mockMvc, String nonceEndpoint, String httpMethod, String httpUri, String accessToken, ECKey dpopKey) {
        // Fetch a fresh nonce
        var nonceResponse = assertDoesNotThrow(() -> mockMvc.perform(post(nonceEndpoint))
                .andExpect(status().isOk())
                .andReturn());
        String dpopNonce = nonceResponse.getResponse().getHeader("DPoP-Nonce");
        return DemonstratingProofOfPossessionTestUtil.createDPoPJWT(httpMethod, httpUri, accessToken, dpopKey, dpopNonce);
    }
}