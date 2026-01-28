package ch.admin.bj.swiyu.issuer.dto.credentialoffer;

import ch.admin.bj.swiyu.issuer.dto.common.ConfigurationOverrideDto;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CreateCredentialOfferRequestDtoTest {

    @Test
    void testBuilderAndGetters() {
        CreateCredentialOfferRequestDto dto = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("id1"))
                .credentialSubjectData("subjectData")
                .offerValiditySeconds(86400)
                .deferredOfferValiditySeconds(604800)
                .credentialValidUntil(Instant.parse("2010-01-01T19:23:24Z"))
                .credentialValidFrom(Instant.parse("2010-01-01T18:23:24Z"))
                .statusLists(List.of("https://example.com/statuslist"))
                .configurationOverride(new ConfigurationOverrideDto(null, null, null, null))
                .build();

        assertEquals(List.of("id1"), dto.getMetadataCredentialSupportedId());
        assertEquals("subjectData", dto.getCredentialSubjectData());
        assertEquals(86400, dto.getOfferValiditySeconds());
        assertEquals(604800, dto.getDeferredOfferValiditySeconds());
        assertEquals(Instant.parse("2010-01-01T19:23:24Z"), dto.getCredentialValidUntil());
        assertEquals(Instant.parse("2010-01-01T18:23:24Z"), dto.getCredentialValidFrom());
        assertEquals(List.of("https://example.com/statuslist"), dto.getStatusLists());
        assertNotNull(dto.getConfigurationOverride());
    }

    @Test
    void testGetStatusListsReturnsEmptyListIfNull() {
        CreateCredentialOfferRequestDto dto = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("id1"))
                .credentialSubjectData("subjectData")
                .build();

        assertNotNull(dto.getStatusLists());
        assertTrue(dto.getStatusLists().isEmpty());
    }
}