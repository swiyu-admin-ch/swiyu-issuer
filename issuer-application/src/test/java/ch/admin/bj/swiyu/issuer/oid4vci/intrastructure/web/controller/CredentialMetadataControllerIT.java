package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.dto.type_metadata.TypeMetadataDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class CredentialMetadataControllerIT {

    @Autowired
    private MockMvc mock;
    @Autowired
    private ObjectMapper mapper;

    private static String calculateSha256Hash(String input) {
        try {
            // Get an instance of MessageDigest for SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Convert the input string to bytes
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

            // Update the digest with the input bytes
            byte[] hashBytes = digest.digest(inputBytes);

            // Encode the hash bytes to a Base64 string
            return String.format("sha256-%s", Base64.getEncoder().encodeToString(hashBytes));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    @Test
    void testCredentialMetadata_matchingHash() throws Exception {
        var mvcResult = mock.perform(MockMvcRequestBuilders.get("/oid4vci/vct/my-vct-v01"))
                .andExpect(status().isOk())
                .andReturn();
        var content = mvcResult.getResponse().getContentAsString();
        // Expected value calculated by running a local instance and in terminal
        // echo "sha256-$(curl -X 'GET' 'http://localhost:8080/json-schema/my-schema-v01' 'accept: application/json' | openssl dgst -sha256 -binary | openssl base64 -A)"
        assertEquals("sha256-0xHwlerZ+FwUtNv+3q0sw0HCQMx9YSEj6Ozq1ugk3Qs=", calculateSha256Hash(content));
        var vctMetadata = mapper.readValue(content, HashMap.class);
        var jsonSchemaResult = mock.perform(MockMvcRequestBuilders.get(vctMetadata.get("schema_uri").toString()))
                .andExpect(status().isOk())
                .andReturn();
        var jsonSchemaContent = jsonSchemaResult.getResponse().getContentAsString();
        assertEquals(vctMetadata.get("schema_uri#integrity").toString(), calculateSha256Hash(jsonSchemaContent));
    }

    @Test
    void checkOCA_thenSuccess() throws Exception {
        var vctResponse = mock.perform(MockMvcRequestBuilders.get("/oid4vci/vct/my-vct-v01"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.display[0].rendering.oca.uri").value("http://localhost:8080/oid4vci/oca/my-oca-v01"))
                .andReturn();

        var typeMetadata = mapper.readValue(vctResponse.getResponse().getContentAsString(), TypeMetadataDto.class);

        mock.perform(MockMvcRequestBuilders.get(typeMetadata.display().getFirst().rendering().oca().uri()))
                .andExpect(status().isOk());
    }
}