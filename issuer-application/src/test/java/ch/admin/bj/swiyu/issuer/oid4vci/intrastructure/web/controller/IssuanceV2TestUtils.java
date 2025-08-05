package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    public static JsonArray extractCredentialsV2(MvcResult response) throws UnsupportedEncodingException {
        var responseJson = JsonParser.parseString(response.getResponse().getContentAsString()).getAsJsonObject();

        return responseJson.get("credentials").getAsJsonArray();
    }

    public void testHolderBindingV2(String vc, ECKey holderPrivateKey) throws ParseException {
        var jwt = SignedJWT.parse(vc.split("~")[0]);
        JsonObject claims = JsonParser.parseString(jwt.getPayload().toString()).getAsJsonObject();
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

    public String getCredentialRequestStringV2(MockMvc mock, List<ECKey> holderPrivateKeys, ApplicationProperties applicationProperties) throws Exception {
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
        return String.format("{\"credential_configuration_id\": \"%s\", \"proofs\": {\"jwt\": [\"%s\"]}}",
                "university_example_sd_jwt",
                proofs.stream().reduce((a, b) -> a + "\", \"" + b).orElse(""));
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
}