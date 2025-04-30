/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.config;

import ch.admin.bj.swiyu.issuer.oid4vci.api.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.oid4vci.api.type_metadata.OcaDto;
import ch.admin.bj.swiyu.issuer.oid4vci.api.type_metadata.TypeMetadataDto;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.CredentialMetadata;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.*;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.PropertyPlaceholderHelper;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@Data
@Slf4j
public class OpenIdIssuerApiConfiguration {

    private final ApplicationProperties applicationProperties;

    private final ResourceLoader resourceLoader;

    private final ObjectMapper objectMapper;

    @Value("${application.openid-file}")
    private Resource openIdResource;

    @Value("${application.metadata-file}")
    private Resource issuerMetadataResource;

    @Cacheable("OpenIdConfiguration")
    public OpenIdConfigurationDto getOpenIdConfiguration() throws IOException {
        return resourceToMappedData(openIdResource, OpenIdConfigurationDto.class);
    }

    /**
     * @return Issuer Metadata for using in creation of a vc
     * @throws IOException if the required json resource is not found
     */
    @Bean
    public IssuerMetadataTechnical getIssuerMetadataTechnical() throws IOException {
        var mapped = resourceToMappedData(issuerMetadataResource, IssuerMetadataTechnical.class);
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        var validator = factory.getValidator();
        var validationResult = validator.validate(mapped).stream()
                .map(v -> String.format("- Invalid value for %s. Current is %s but the constraint is %s", v.getPropertyPath().toString(), v.getInvalidValue(), v.getMessage()))
                .collect(Collectors.joining("\n"));
        if (!validationResult.isEmpty()) {
            throw new IllegalArgumentException(String.format("An invalid issuer metadata configuration was provided. Please adapt the following values:\n%s", validationResult));
        }
        return mapped;
    }

    @Bean
    public CredentialMetadata getCredentialMetadata() throws IOException {
        var builder = CredentialMetadata.builder();

        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory();) {
            Validator validator = factory.getValidator();

            builder.vctMetadataMap(loadMetadataFiles(applicationProperties.getVctMetadataFiles(), validator, TypeMetadataDto.class));
            builder.jsonSchemaMap(loadMetadataFiles(applicationProperties.getJsonSchemaMetadataFiles(), validator, null));
            builder.overlayCaptureArchitectureMap(loadMetadataFiles(applicationProperties.getOverlaysCaptureArchitectureMetadataFiles(), validator, OcaDto.class));
            return builder.build();
        }
    }

    public <T> Map<String, String> loadMetadataFiles(Map<String, String> metadataFiles, Validator validator, Class<T> clazz) throws IOException {
        var metadata = new HashMap<String, String>();
        if (metadataFiles == null) {
            return metadata;
        }
        for (Map.Entry<String, String> entry : metadataFiles.entrySet()) {
            var resource = resourceLoader.getResource(entry.getValue());
            if (!resource.exists()) {
                log.error("Could not find configured resource: {}", entry.getValue());
                continue;
            }

            if (validator != null && clazz != null) {
                validateMetadataFile(entry, validator, clazz);
            }

            log.debug("Loading metadata {}: {}", entry.getKey(), entry.getValue());
            metadata.put(entry.getKey(), loadMetadata(resource));
        }
        return metadata;
    }

    public <T> void validateMetadataFile(Map.Entry<String, String> entry, Validator validator, Class<T> clazz) throws IOException {
        var resource = resourceLoader.getResource(entry.getValue());
        var metadataFileContent = loadMetadata(resource);

        T metadata = objectMapper.readValue(metadataFileContent, clazz);
        Set<ConstraintViolation<T>> violations = validator.validate(metadata);
        if (!violations.isEmpty()) {
            log.error("Validation error in {} with message: {}", entry.getValue(), violations);
            throw new ConstraintViolationException(violations);
        }
    }

    private String replaceExternalUri(String template) {
        Properties prop = new Properties();
        for (Map.Entry<String, String> replacementEntrySet : applicationProperties.getTemplateReplacement().entrySet()) {
            prop.setProperty(replacementEntrySet.getKey(), replacementEntrySet.getValue());
        }
        PropertyPlaceholderHelper helper = new PropertyPlaceholderHelper("${", "}");
        return helper.replacePlaceholders(template, prop);
    }

    private <T> T resourceToMappedData(Resource res, Class<T> clazz) throws IOException {
        var json = res.getContentAsString(Charset.defaultCharset());
        json = replaceExternalUri(json);
        return new ObjectMapper().readValue(json, clazz);
    }

    /**
     * Loads metadata, replacing placeholders
     *
     * @param res resource from which the data is loaded
     * @return the loaded metadata
     */
    private String loadMetadata(Resource res) throws IOException {
        var json = res.getContentAsString(Charset.defaultCharset());
        return replaceExternalUri(json);
    }

}