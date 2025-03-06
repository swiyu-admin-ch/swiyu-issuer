/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.it;

import ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller.CredentialController;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("test")
public class IssuerManagementApplicationIT {

    public static final String privateKey = """
               	{
            "kty":"EC",
            "d":"L5IOdH7GqpjqxeXRaQZvYNFs2qPdMVdNR1ohV0gjYVc",
            "crv":"P-256",
            "kid":"testkey",
            "x":"_gHQsZT-CB_KvIfpvJsDxVSXkuwRJsuof-oMihcupQU",
            "y":"71y_zEPAglUXBghaBxypTAzlNx57KNY9lv8LTbPkmZA"
            }""";
    @Autowired
    private CredentialController credentialController;

    @Test
    void contextLoads() {
        assertThat(credentialController).isNotNull();
    }

    @Test
    void dummyTest() throws JOSEException {

        String testdata = """
                {
                   "keys":[
                      {
                         "kty":"EC",
                         "crv":"P-256",
                         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                         "use":"enc",
                         "kid":"1"
                      },
                      {
                         "kty":"RSA",
                         "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
                				4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
                				tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
                				QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
                				SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
                				w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                         "e":"AQAB",
                         "alg":"RS256",
                         "kid":"2011-04-29"
                      },
                      {
                         "kty":"EC",
                         "crv":"P-256",
                         "kid":"testkey",
                         "x":"_gHQsZT-CB_KvIfpvJsDxVSXkuwRJsuof-oMihcupQU",
                         "y":"71y_zEPAglUXBghaBxypTAzlNx57KNY9lv8LTbPkmZA"
                      }
                   ]
                }""";

        try {
            ECKey ecJWK = ECKey.parse(privateKey);
            JWKSet jwks = JWKSet.parse(testdata);
            JWSSigner signer = new ECDSASigner(ecJWK);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("alice")
                    .issuer("http://localhost:8080")
                    .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecJWK.getKeyID()).build(),
                    claims);
            jwt.sign(signer);
            String jwtString = jwt.serialize();

            SignedJWT receivedJWT = SignedJWT.parse(jwtString);
            JWK jwk = jwks.getKeyByKeyId(receivedJWT.getHeader().getKeyID());
            JWSVerifier verifier = new ECDSAVerifier(jwk.toECKey().toPublicJWK());
            assertTrue(receivedJWT.verify(verifier));

        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testHttpMaxRedirectsSystemPropertyIsSet() {
        var maxRedirects = System.getProperty("http.maxRedirects");
        assertEquals("5", maxRedirects);
    }

}
