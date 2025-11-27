package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class WellKnownControllerIT {
    @Autowired
    private MockMvc mock;

    @Test
    void testGetOpenIdConfiguration_thenSuccess() throws Exception {
        mock.perform(get("/oid4vci/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("token_endpoint")))
                .andExpect(content().string(not(containsString("${external-url}"))));
    }

    @Test
    void testGetOauthAuthorizationServer_thenSuccess() throws Exception {
        mock.perform(get("/oid4vci/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("token_endpoint")))
                .andExpect(content().string(not(containsString("${external-url}"))));
    }

    @Test
    void testGetIssuerMetadata_thenSuccess() throws Exception {
        mock.perform(get("/oid4vci/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("${external-url}"))))
                .andExpect(content().string(containsString("credential_endpoint")))
                .andExpect(content().string(not(containsString("${stage}")))) // stage placeholder should be replace
                .andExpect(content().string(containsString("local-Example Credential"))) // Replaced placeholder examples
                .andExpect(content().string(containsString("local-university_example_sd_jwt")))
                .andExpect(content().string(containsString("\"vct_metadata_uri\""))) // vct metadata indirection should not be filtered out if used
                .andExpect(content().string(containsString("\"vct_metadata_uri#integrity\""))) // integrity for vct metadata indirection should not be filtered out if used
                .andExpect(content().string(Matchers.not(containsString("issuanceBatchSize")))); // Util Field should not be displayed metadata
    }
}
