package ch.admin.bj.swiyu.issuer.service.offer;

import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfigurationMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.MetadataClaimDescriptor;
import ch.admin.bj.swiyu.issuer.dto.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.issuer.service.DataIntegrityService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link CredentialOfferValidationService}.
 *
 * <p>Focus: pure validation rules and wiring (no persistence). Each test targets a specific rule/branch.</p>
 */
class CredentialOfferValidationServiceTest {

    private IssuerMetadata issuerMetadata;
    private DataIntegrityService dataIntegrityService;
    private CredentialOfferValidationService validationService;

    @BeforeEach
    void setUp() {
        issuerMetadata = mock(IssuerMetadata.class);
        dataIntegrityService = mock(DataIntegrityService.class);
        validationService = new CredentialOfferValidationService(issuerMetadata, dataIntegrityService);
    }

    /**
     * Supported formats must pass.
     */
    @Test
    void validateCredentialFormat_shouldPassForValidFormat() {
        var credentialConfiguration = mock(CredentialConfiguration.class);
        when(credentialConfiguration.getFormat()).thenReturn("dc+sd-jwt");

        assertDoesNotThrow(() -> validationService.validateCredentialFormat(credentialConfiguration));
    }

    /**
     * Unsupported formats must fail.
     */
    @Test
    void validateCredentialFormat_shouldThrowForInvalidFormat() {
        var credentialConfiguration = mock(CredentialConfiguration.class);
        when(credentialConfiguration.getFormat()).thenReturn("invalid-format");

        assertThrows(IllegalStateException.class,
                () -> validationService.validateCredentialFormat(credentialConfiguration));
    }

    @Test
    void validateOfferedCredentialValiditySpan_shouldThrowIfExpired() {
        var request = CreateCredentialOfferRequestDto.builder()
                .credentialValidUntil(Instant.now().minusSeconds(100))
                .build();

        assertThrows(BadRequestException.class,
                () -> validationService.validateOfferedCredentialValiditySpan(request));
    }

    @Test
    void validateOfferedCredentialValiditySpan_shouldThrowIfValidFromAfterValidUntil() {
        var validFrom = Instant.now().plusSeconds(200);
        var validUntil = Instant.now().plusSeconds(100);

        var request = CreateCredentialOfferRequestDto.builder()
                .credentialValidFrom(validFrom)
                .credentialValidUntil(validUntil)
                .build();

        assertThrows(BadRequestException.class,
                () -> validationService.validateOfferedCredentialValiditySpan(request));
    }

    @Test
    void validateOfferedCredentialValiditySpan_shouldPassForValidSpan() {
        var validFrom = Instant.now().plusSeconds(100);
        var validUntil = Instant.now().plusSeconds(200);

        var request = CreateCredentialOfferRequestDto.builder()
                .credentialValidFrom(validFrom)
                .credentialValidUntil(validUntil)
                .build();

        assertDoesNotThrow(() -> validationService.validateOfferedCredentialValiditySpan(request));
    }

    /**
     * Deferred requests may omit offerData initially.
     */
    @Test
    void validateCredentialRequestOfferData_shouldAllowEmptyOfferData_whenDeferred() {
        var credConfig = mock(CredentialConfiguration.class);

        assertDoesNotThrow(() ->
                validationService.validateCredentialRequestOfferData(Map.of(), true, credConfig));

        verifyNoInteractions(dataIntegrityService);
    }

    /**
     * Non-deferred requests must provide offerData.
     */
    @Test
    void validateCredentialRequestOfferData_shouldThrow_whenOfferDataEmptyAndNotDeferred() {
        var credConfig = mock(CredentialConfiguration.class);

        assertThrows(BadRequestException.class, () ->
                validationService.validateCredentialRequestOfferData(Map.of(), false, credConfig));
    }

    /**
     * Protected claims must never occur in credentialSubjectData.
     */
    @Test
    void validateCredentialRequestOfferData_shouldThrow_whenOfferDataContainsProtectedClaim() {
        var credConfig = mock(CredentialConfiguration.class);

        Map<String, Object> offerData = Map.of("iss", "did:example:bad");
        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(offerData);

        assertThrows(BadRequestException.class, () ->
                validationService.validateCredentialRequestOfferData(offerData, false, credConfig));
    }

    @Test
    void validateCredentialRequestOfferData_shouldThrow_whenMandatoryClaimMissing() {
        var mandatory = new MetadataClaimDescriptor();
        mandatory.setMandatory(true);
        mandatory.setPath(List.of("must"));

        var optional = new MetadataClaimDescriptor();
        optional.setMandatory(false);
        optional.setPath(List.of("opt"));

        CredentialConfigurationMetadata credentialConfigurationMetadata = new CredentialConfigurationMetadata();
        credentialConfigurationMetadata.setClaimDescriptor(List.of(mandatory, optional));

        var credConfig = mock(CredentialConfiguration.class);
        when(credConfig.getCredentialMetadata()).thenReturn(credentialConfigurationMetadata);

        Map<String, Object> offerData = Map.of("opt", "present");
        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(offerData);

        BadRequestException ex = assertThrows(BadRequestException.class, () ->
                validationService.validateCredentialRequestOfferData(offerData, false, credConfig));

        assertTrue(ex.getMessage().contains("Mandatory credential claims are missing"));
        assertTrue(ex.getMessage().contains("must"));
    }

    @Test
    void validateCredentialRequestOfferData_shouldSucceed_whenSurplusClaimPresent() {
        var claim = new MetadataClaimDescriptor();
        claim.setPath(List.of("allowed"));
        claim.setMandatory(true);

        CredentialConfigurationMetadata credentialConfigurationMetadata = new CredentialConfigurationMetadata();
        credentialConfigurationMetadata.setClaimDescriptor(List.of(claim));

        var credConfig = mock(CredentialConfiguration.class);
        when(credConfig.getCredentialMetadata()).thenReturn(credentialConfigurationMetadata);

        Map<String, Object> offerData = Map.of("allowed", "ok", "unexpected", "nope");
        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(offerData);

        assertDoesNotThrow(() ->
                validationService.validateCredentialRequestOfferData(offerData, false, credConfig));
    }

    @Test
    void validateCredentialOfferCreateRequest_shouldValidateFormatDatesAndClaims() {
        var mandatory = new MetadataClaimDescriptor();
        mandatory.setMandatory(true);

        var credConfig = mock(CredentialConfiguration.class);
        when(credConfig.getFormat()).thenReturn("vc+sd-jwt");

        when(issuerMetadata.getCredentialConfigurationById("test")).thenReturn(credConfig);

        var request = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(Map.of("hello", "world"))
                .credentialValidFrom(Instant.now().plusSeconds(10))
                .credentialValidUntil(Instant.now().plusSeconds(3600))
                .credentialMetadata(new CredentialOfferMetadataDto(false, null, null))
                .build();

        Map<String, Object> offerData = Map.of("hello", "world");
        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(offerData);

        assertDoesNotThrow(() -> validationService.validateCredentialOfferCreateRequest(request, offerData));

        verify(issuerMetadata, times(1)).getCredentialConfigurationById("test");
        verify(dataIntegrityService, times(1)).getVerifiedOfferData(eq(offerData), isNull());
    }

    @Test
    void validateCredentialOfferCreateRequest_withMissingValue_throwsIllegalArgumentException() throws JsonProcessingException {

        Map<String, Object> validatedOfferData = Map.of("path", List.of());
        Map<String, Object> offerData = Map.of("data", validatedOfferData);

        var credentialMetadata = """
                {
                    "claims": [
                        {
                            "path": ["mandatory"],
                            "mandatory": true
                        },
                        {
                            "path": ["additional_info_list"],
                            "mandatory": false
                        }
                    ]
                }
                """;

        mockCredentialConfigInteractions(credentialMetadata);

        var request = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialValidFrom(Instant.now().plusSeconds(10))
                .credentialValidUntil(Instant.now().plusSeconds(3600))
                .credentialMetadata(new CredentialOfferMetadataDto(false, null, null))
                .build();

        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(validatedOfferData);

        var ex = assertThrows(BadRequestException.class, () -> validationService.validateCredentialOfferCreateRequest(request, offerData));
        assertEquals("Mandatory credential claims are missing: [mandatory]", ex.getMessage());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void validateCredentialOfferCreateRequest_withEmptyArray_throwsIllegalArgumentException(boolean mandatory) throws JsonProcessingException {

        Map<String, Object> validatedOfferData = Map.of("path", List.of());
        Map<String, Object> offerData = Map.of("data", validatedOfferData);

        var credentialMetadata = """
                {
                    "claims": [
                        {
                            "path": ["path"],
                            "mandatory": %s
                        }
                    ]
                }
                """.formatted(mandatory);

        mockCredentialConfigInteractions(credentialMetadata);

        var request = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialValidFrom(Instant.now().plusSeconds(10))
                .credentialValidUntil(Instant.now().plusSeconds(3600))
                .credentialMetadata(new CredentialOfferMetadataDto(false, null, null))
                .build();

        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(validatedOfferData);

        assertDoesNotThrow(() -> validationService.validateCredentialOfferCreateRequest(request, offerData));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void validateCredentialOfferCreateRequest_withEmptyObject_throwsIllegalArgumentException(boolean mandatory) throws JsonProcessingException {

        Map<String, Object> validatedOfferData = Map.of("additional_info_map", Map.of());
        Map<String, Object> offerData = Map.of("data", validatedOfferData);

        var credentialMetadata = """
                {
                    "claims": [
                        {
                            "path": ["additional_info_map"],
                            "mandatory": %s
                        }
                    ]
                }
                """.formatted(mandatory);

        mockCredentialConfigInteractions(credentialMetadata);

        var request = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialValidFrom(Instant.now().plusSeconds(10))
                .credentialValidUntil(Instant.now().plusSeconds(3600))
                .credentialMetadata(new CredentialOfferMetadataDto(false, null, null))
                .build();

        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(validatedOfferData);

        assertDoesNotThrow(() -> validationService.validateCredentialOfferCreateRequest(request, offerData));
    }

    @Test
    void validateCredentialOfferCreateRequest_withListAndNullValue_throwsBadRequestException() throws JsonProcessingException {

        var additionalInfoList = new ArrayList<>();
        additionalInfoList.add(null);
        Map<String, Object> offerData = Map.of("path", Map.of("additional_info_list", additionalInfoList));

        var credentialMetadata = """
                {
                    "claims": [
                        {
                            "path": ["additional_info_list"],
                            "mandatory": true
                        }
                    ]
                }
                """;

        mockCredentialConfigInteractions(credentialMetadata);

        var request = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialValidFrom(Instant.now().plusSeconds(10))
                .credentialValidUntil(Instant.now().plusSeconds(3600))
                .credentialMetadata(new CredentialOfferMetadataDto(false, null, null))
                .build();
        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(offerData);


        assertThrows(BadRequestException.class, () -> validationService.validateCredentialOfferCreateRequest(request, offerData));
    }

    @Test
    void validateCredentialOfferCreateRequest_withUnsupportedMetadataCredentialId_throwsIllegalArgumentException() {
        var mandatory = new MetadataClaimDescriptor();
        mandatory.setMandatory(true);

        var credConfig = mock(CredentialConfiguration.class);
        when(credConfig.getFormat()).thenReturn("vc+sd-jwt");

        when(issuerMetadata.getCredentialConfigurationById("test")).thenReturn(credConfig);
        when(issuerMetadata.getCredentialConfigurationById("unsupported")).thenThrow(new BadRequestException("Unsupported credential offer metadata"));

        var request = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test", "unsupported"))
                .credentialSubjectData(Map.of("hello", "world"))
                .credentialValidFrom(Instant.now().plusSeconds(10))
                .credentialValidUntil(Instant.now().plusSeconds(3600))
                .credentialMetadata(new CredentialOfferMetadataDto(false, null, null))
                .build();

        Map<String, Object> offerData = Map.of("hello", "world");

        var ex = assertThrows(BadRequestException.class, () -> validationService.validateCredentialOfferCreateRequest(request, offerData));
        assertThat(ex.getMessage()).contains("Unsupported credential offer metadata");

        verify(issuerMetadata, atLeastOnce()).getCredentialConfigurationById(any());
        verify(dataIntegrityService, atMostOnce()).getVerifiedOfferData(eq(offerData), isNull());
    }

    @Test
    void validateCredentialOfferCreateRequest_withListAndNullValue_throwsIllegalArgumentException2() throws JsonProcessingException {

        var additionalInfoList = new ArrayList<>();
        additionalInfoList.add("test");
        Map<String, Object> validatedOfferData = Map.of("test", "test", "additional_info_list", additionalInfoList, "additional_info_list_2", List.of(Map.of("additional_info_map", "additional_info_map")));
        Map<String, Object> offerData = Map.of("data", validatedOfferData);

        var credentialMetadata = """
                {
                    "claims": [
                        {
                            "path": ["test"],
                            "mandatory": true
                        },
                        {
                            "path": ["additional_info_list"],
                            "mandatory": true
                        },
                        {
                            "path": ["additional_info_list_2", null, "additional_info_map"],
                            "mandatory": true
                        }
                    ]
                }
                """;

        mockCredentialConfigInteractions(credentialMetadata);

        var request = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialValidFrom(Instant.now().plusSeconds(10))
                .credentialValidUntil(Instant.now().plusSeconds(3600))
                .credentialMetadata(new CredentialOfferMetadataDto(true, null, null))
                .build();

        when(dataIntegrityService.getVerifiedOfferData(eq(offerData), isNull())).thenReturn(validatedOfferData);

        assertDoesNotThrow(() -> validationService.validateCredentialOfferCreateRequest(request, offerData));
    }

    @Test
    void determineIssuerDid_shouldReturnOverrideIfPresent() {
        var request = CreateCredentialOfferRequestDto.builder()
                .configurationOverride(new ConfigurationOverrideDto("did:example:override", null, null, null))
                .build();

        String did = validationService.determineIssuerDid(request, "did:example:default");
        assertEquals("did:example:override", did);
    }

    @Test
    void determineIssuerDid_shouldReturnDefaultIfOverrideAbsent() {
        var request = CreateCredentialOfferRequestDto.builder().build();

        String did = validationService.determineIssuerDid(request, "did:example:default");
        assertEquals("did:example:default", did);
    }

    @Test
    void ensureMatchingIssuerDids_shouldPass_whenAllMatch() {
        var statusLists = List.of(
                StatusList.builder()
                        .uri("https://example.com/status")
                        .configurationOverride(new ConfigurationOverride(null, null, null, null))
                        .build()
        );

        assertDoesNotThrow(() ->
                validationService.ensureMatchingIssuerDids("did:example:123", "did:example:123", statusLists));
    }

    @Test
    void ensureMatchingIssuerDids_shouldThrow_whenAnyMismatch() {
        var statusLists = List.of(
                StatusList.builder()
                        .uri("https://example.com/status")
                        .configurationOverride(new ConfigurationOverride("did:example:OTHER", null, null, null))
                        .build()
        );

        BadRequestException ex = assertThrows(BadRequestException.class, () ->
                validationService.ensureMatchingIssuerDids("did:example:123", "did:example:123", statusLists));

        assertTrue(ex.getMessage().contains("Status List issuer did is not the same"));
        assertTrue(ex.getMessage().contains("https://example.com/status"));
    }

    private void mockCredentialConfigInteractions(String credentialMetadata) throws JsonProcessingException {
        var objectMapper = new ObjectMapper();
        var credConfig = mock(CredentialConfiguration.class);
        when(credConfig.getCredentialMetadata()).thenReturn(objectMapper.readValue(credentialMetadata, CredentialConfigurationMetadata.class));
        when(credConfig.getFormat()).thenReturn("vc+sd-jwt");
        when(issuerMetadata.getCredentialConfigurationById("test")).thenReturn(credConfig);
    }
}