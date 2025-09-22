/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialOfferDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonParser;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.lang3.RandomStringUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.common.date.DateTimeUtils.ISO8601_FORMAT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest()
@Nested
@DisplayName("Create Offer")
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class CredentialOfferCreateIT {

    private static final String BASE_URL = "/management/api/credentials";

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

        var credentialOffer = objectMapper.readValue(credentialOfferString, CredentialOfferDto.class);
        String preAuthorizedCode = credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString();
        assertNotSame(preAuthorizedCode, managementId);

        String now = new SimpleDateFormat(ISO8601_FORMAT).format(new Date(new Date().getTime() + 1000));
        String minPayloadWithValidUntil = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}, \"credential_valid_until\" : \"%s\"}",
                "test", now);
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithValidUntil))
                .andExpect(status().isOk());
    }

    @Test
    void testCreateOffer_InPast_thenFailure() throws Exception {
        String now = "2025-02-25T15:55:11Z";
        String minPayloadWithValidUntil = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}, \"credential_valid_until\" : \"%s\"}",
                "test", now);
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithValidUntil))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(Matchers.containsString("expired")));
    }

    @Test
    void testCreateOffer_unexpectedClaim_thenBadRequest() throws Exception {
        String minPayloadWithValidUntil = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"%s\": \"arbitrary claim\"}}",
                "test", UUID.randomUUID());
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithValidUntil))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(Matchers.containsString("Unexpected credential claims found")));
    }

    @Test
    void testCreateOffer_missingClaim_thenBadRequest() throws Exception {
        String minPayloadWithValidUntil = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"average_grade\": 5.5}}",
                "university_example_sd_jwt");
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithValidUntil))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(Matchers.containsString("Mandatory credential claims are missing")));
    }

    @Test
    void testCreateOffer_noMilliseconds_thenSuccess() throws Exception {
        String validUntilNoMilliseconds = "3025-02-25T15:55:11Z";
        String minPayloadWithValidUntil = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}, \"credential_valid_until\" : \"%s\"}",
                "test", validUntilNoMilliseconds);
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithValidUntil))
                .andExpect(status().isOk());
    }

    @Test
    void testCreateOffer_validFrom_after_validUntil_thenBadRequest() throws Exception {
        String validUntilNoMilliseconds = "3025-02-25T15:55:11Z";
        String validFromNoMilliseconds = "4025-02-25T15:55:11Z";
        String minPayloadWithValidUntil = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}, \"credential_valid_until\" : \"%s\", \"credential_valid_from\" : \"%s\"}",
                "test", validUntilNoMilliseconds, validFromNoMilliseconds);
        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithValidUntil))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(Matchers.containsString("Credential would never be valid")));
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
                .andExpect(status().isUnprocessableEntity());

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
                .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.OFFERED.name()))
                .andExpect(jsonPath("$.metadata_credential_supported_id").isArray())
                .andExpect(jsonPath("$.credential_metadata").isMap())
                .andExpect(jsonPath("$.credential_metadata").isEmpty())
                .andExpect(jsonPath("$.holder_jwks").isEmpty())
                .andExpect(jsonPath("$.client_agent_info").isEmpty())
                .andExpect(jsonPath("$.offer_deeplink").isNotEmpty());
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
        assertEquals(testIntegrity, credentialOfferRepository.findById(UUID.fromString(id)).orElseThrow().getCredentialMetadata().vctIntegrity());
    }

    @Test
    void testCreateOfferVcMetadata_metadataIntegration_thenSuccess() throws Exception {
        String jsonPayload = """
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": {
                    "hello": "world"
                  },
                  "offer_validity_seconds": 36000,
                  "credential_metadata": {
                    "vct_metadata_uri": "https://example.com/credentials/vct/metadata.json",
                    "vct_metadata_uri#integrity": "sha256-TmHzu3DojO4MFaBXcJ6akg8JY/JWOcDU8PfUViEMYKk="
                  }
                }
                """;

        var response = mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isOk())
                .andReturn();

        var responseJson = JsonParser.parseString(response.getResponse().getContentAsString()).getAsJsonObject();

        mvc.perform(get(BASE_URL + "/" + responseJson.get("management_id").getAsString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_metadata.vct_metadata_uri").value("https://example.com/credentials/vct/metadata.json"))
                .andExpect(jsonPath("$.credential_metadata['vct_metadata_uri#integrity']").value("sha256-TmHzu3DojO4MFaBXcJ6akg8JY/JWOcDU8PfUViEMYKk="))
                .andReturn();
    }

    @Test
    void testCreateOfferVcMetadata_blankUri_thenBadRequest() throws Exception {
        String jsonPayload = """
                {
                  "metadata_credential_supported_id": ["test"],
                  "credential_subject_data": {
                    "hello": "world"
                  },
                  "offer_validity_seconds": 36000,
                  "credential_metadata": {
                    "vct_metadata_uri": ""
                  }
                }
                """;

        var response = mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isUnprocessableEntity())
                .andReturn();

        var responseJson = JsonParser.parseString(response.getResponse().getContentAsString()).getAsJsonObject();

        assertEquals("Unprocessable Entity", responseJson.get("error_description").getAsString());
        assertEquals("credentialMetadata.vctMetadataUri: If provided, vct_metadata_uri must not be blank", responseJson.get("detail").getAsString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"sub", "iss", "nbf", "exp", "iat", "cnf", "vct", "status", "_sd", "_sd_alg", "sd_hash", "..."})
    void testProtectedClaimsInOfferData_thenBadRequest(String claim) throws Exception {

        String jsonPayload = """
                {
                  "metadata_credential_supported_id": ["university_example_sd_jwt"],
                  "credential_subject_data": {
                    "%s": "protected claim"
                  },
                  "offer_validity_seconds": 36000
                }
                """.formatted(claim);

        mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("The following claims are not allowed in the credentialSubjectData: [%s]".formatted(claim)))
                .andReturn();
    }
}