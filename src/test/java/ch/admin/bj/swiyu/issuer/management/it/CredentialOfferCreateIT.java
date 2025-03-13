/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.it;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.management.common.date.DateTimeUtils.ISO8601_FORMAT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest()
@ActiveProfiles("test")
@Nested
@DisplayName("Create Offer")
@AutoConfigureMockMvc
class CredentialOfferCreateIT {

    private static final String BASE_URL = "/api/v1/credentials";

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialOfferRepository credentialOfferRepository;

    @Autowired
    private MockMvc mvc;

    @Test
    void testCreateOffer_thenSuccess() throws Exception {
        String minPayloadWithEmptySubject = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}}",
                "test");

        var test = mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.management_id").isNotEmpty())
                .andExpect(jsonPath("$.offer_deeplink").isNotEmpty())
                .andReturn();

        // CredentialWithDeeplinkResponseDto
        String urlEncodedDeeplink = JsonPath.read(test.getResponse().getContentAsString(), "$.offer_deeplink");
        String managementId = JsonPath.read(test.getResponse().getContentAsString(), "$.management_id");

        // decode deeplink should not throw an exception
        var deeplink = URLDecoder.decode(urlEncodedDeeplink, StandardCharsets.UTF_8);
        var credentialOfferString = deeplink.replace("swiyu://?credential_offer=", "");

        var credentialOffer = objectMapper.readValue(credentialOfferString, Map.class);
        Map<?, ?> grants = (Map<?, ?>) credentialOffer.get("grants");
        String preAuthorizedCode = ((Map<String, String>) grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")).get("pre-authorized_code");
        assertNotSame(preAuthorizedCode, managementId);

        String now = new SimpleDateFormat(ISO8601_FORMAT).format(new Date());
        String minPayloadWithValidUntil = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}, \"credential_valid_until\" : \"%s\"}",
                "test", now);
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithValidUntil))
                .andExpect(status().isOk());
    }

    @Test
    void testCreateOffer_noMilliseconds_thenSuccess() throws Exception {
        String minPayloadWithEmptySubject = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}}",
                "test");
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.management_id").isNotEmpty())
                .andExpect(jsonPath("$.offer_deeplink").isNotEmpty());

        String now = "2025-02-25T15:55:11Z";
        String minPayloadWithValidUntil = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}, \"credential_valid_until\" : \"%s\"}",
                "test", now);
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithValidUntil))
                .andExpect(status().isOk());
    }

    @Test
    void testCreateOffer_thenValidationFailure() throws Exception {
        String emptyMetadataId = String.format(
                "{\"metadata_credential_supported_id\": \"%s\", \"credential_subject_data\": {}}", "");

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(emptyMetadataId))
                .andExpect(status().isBadRequest());

        String noCredentialSubject = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": null}",
                "");

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(noCredentialSubject))
                .andExpect(status().isBadRequest());

        String invalidValidUntilPattern = String.format(
                "{\"metadata_credential_supported_id\": \"%s\", \"credential_subject_data\": {}, \"credential_valid_until\" : \"2010-01-01T19:23:24.111\"}",
                RandomStringUtils.insecure().next(10));

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(invalidValidUntilPattern))
                .andExpect(status().isBadRequest());

        // Check Invalid JSON payloads in credential_subject_data
        String invalidValidFromPattern = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {}, \"credential_valid_from\" : \"2010-01-01T19:23:24.111\"}",
                RandomStringUtils.insecure().next(10));

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(invalidValidFromPattern))
                .andExpect(status().isBadRequest());

        String invalidJson = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"test\"}}",
                RandomStringUtils.insecure().next(10));
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(invalidJson))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testGetOfferData_thenSuccess() throws Exception {

        String offerData = "{\"hello\":\"world\"}";

        String jsonPayload = """
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": {
                    "hello": "world"
                  },
                  "offer_validity_seconds": 36000
                }
                """;

        MvcResult result = mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isOk())
                .andReturn();

        String id = JsonPath.read(result.getResponse().getContentAsString(), "$.management_id");

        mvc.perform(get(String.format("%s/%s", BASE_URL, id)))
                .andExpect(status().isOk())
                .andExpect(content().string(offerData));
    }

    @Test
    void testCreateOfferVcMetadata_thenSuccess() throws Exception {
        String testIntegrity = "sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=";
        String jsonPayload = String.format("""
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": {
                    "hello": "world"
                  },
                  "offer_validity_seconds": 36000,
                  "credential_metadata": {
                    "vct#integrity": "%s"
                  }
                }
                """, testIntegrity);

        MvcResult result = mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isOk())
                .andReturn();
        String id = JsonPath.read(result.getResponse().getContentAsString(), "$.management_id");
        assertEquals(testIntegrity, credentialOfferRepository.findById(UUID.fromString(id)).orElseThrow().getCredentialMetadata().get("vct#integrity"));
    }

}
