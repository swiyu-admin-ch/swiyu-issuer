package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.ClientAgentInfoDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CredentialOfferMapperTest {

    @Test
    void toCredentialWithDeeplinkResponseDto_mapsFieldsCorrectly() {
        var id = UUID.randomUUID();
        CredentialOffer offer = mock(CredentialOffer.class);
        CredentialManagement mgmt = mock(CredentialManagement.class);
        when(mgmt.getId()).thenReturn(id);
        when(mgmt.getPreAuthorizedCode()).thenReturn(id);
        when(offer.getId()).thenReturn(id);
        when(offer.getCredentialManagement()).thenReturn(mgmt);
        ApplicationProperties props = mock(ApplicationProperties.class);

        CredentialWithDeeplinkResponseDto dto = CredentialOfferMapper.toCredentialWithDeeplinkResponseDto(props, mgmt, offer);

        assertEquals(id, dto.getManagementId());
    }

    @Test
    void toCredentialInfoResponseDto_mapsAllFields() {
        ApplicationProperties props = mock(ApplicationProperties.class);
        CredentialManagement mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .build();
        CredentialOfferMetadata credentialOfferMetadata = CredentialOfferMetadata.builder()
                .deferred(false)
                .vctIntegrity("vct#integrity")
                .build();
        CredentialOffer offer = getCredentialOffer(credentialOfferMetadata, mgmt);

        CredentialInfoResponseDto dto = CredentialOfferMapper.toCredentialInfoResponseDto(offer, props);

        assertEquals(CredentialStatusTypeDto.OFFERED, dto.credentialStatus());
        assertEquals(List.of("id1"), dto.metadataCredentialSupportedId());
        assertEquals(List.of("jwk1", "jwk2"), dto.holderJWKs());
        assertNotNull(dto.clientAgentInfo());
        assertEquals("ip", dto.clientAgentInfo().remoteAddr());

        assertEquals(false, dto.credentialMetadata().deferred());
        assertEquals("vct#integrity", dto.credentialMetadata().vctIntegrity());
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(booleans = {true, false})
    void toCredentialInfoResponseDto_deferred(Boolean deferred) {
        ApplicationProperties props = mock(ApplicationProperties.class);
        CredentialManagement mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .build();

        CredentialOfferMetadata credentialOfferMetadata = CredentialOfferMetadata.builder()
                .deferred(deferred)
                .build();

        CredentialOffer offer = getCredentialOffer(credentialOfferMetadata, mgmt);

        CredentialInfoResponseDto dto = CredentialOfferMapper.toCredentialInfoResponseDto(offer, props);

        assertEquals(deferred, dto.credentialMetadata().deferred());
        assertNull(dto.credentialMetadata().vctIntegrity());
    }

    @Test
    void toClientAgentInfoDto_returnsNullIfInputNull() {
        assertNull(CredentialOfferMapper.toClientAgentInfoDto(null));
    }

    @Test
    void toClientAgentInfoDto_mapsFields() {
        ClientAgentInfo info = new ClientAgentInfo("ip", "ua", "lang", "enc");
        ClientAgentInfoDto dto = CredentialOfferMapper.toClientAgentInfoDto(info);

        assertEquals("ip", dto.remoteAddr());
        assertEquals("ua", dto.userAgent());
        assertEquals("lang", dto.acceptLanguage());
        assertEquals("enc", dto.acceptEncoding());
    }

    @Test
    void toCredentialWithDeeplinkResponseDto_returnsDataIfPresent() {
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getOfferData()).thenReturn(Map.of("data", "value"));
        Object result = CredentialOfferMapper.toCredentialWithDeeplinkResponseDto(offer);
        assertEquals("value", result);
    }

    @Test
    void toCredentialWithDeeplinkResponseDto_returnsOfferDataIfNoDataKey() {
        CredentialOffer offer = mock(CredentialOffer.class);
        Map<String, Object> offerData = Map.of("other", "value");
        when(offer.getOfferData()).thenReturn(offerData);
        Object result = CredentialOfferMapper.toCredentialWithDeeplinkResponseDto(offer);
        assertEquals(offerData, result);
    }

    @Test
    void toUpdateStatusResponseDto_mapsFields() {
        var id = UUID.randomUUID();
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getId()).thenReturn(id);
        when(offer.getCredentialStatus()).thenReturn(CredentialStatusType.ISSUED);

        UpdateStatusResponseDto dto = CredentialOfferMapper.toUpdateStatusResponseDto(offer);

        assertEquals(id, dto.getId());
        assertEquals(CredentialStatusTypeDto.ISSUED, dto.getCredentialStatus());
    }

    @Test
    void toCredentialStatusType_fromDto() {
        assertEquals(CredentialStatusType.OFFERED, CredentialOfferMapper.toCredentialStatusType(CredentialStatusTypeDto.OFFERED));
        assertNull(null);
    }

    @Test
    void toCredentialStatusType_fromUpdateRequestDto() {
        assertEquals(CredentialStatusType.CANCELLED, CredentialOfferMapper.toCredentialStatusType(UpdateCredentialStatusRequestTypeDto.CANCELLED));
        assertNull(null);
    }

    @Test
    void toCredentialOfferMetadataDto_returnsNullIfInputNull() {
        assertNull(CredentialOfferMapper.toCredentialOfferMetadataDto(null));
    }

    @Test
    void toCredentialOfferMetadataDto_mapsFieldsCorrectly() {
        CredentialOfferMetadataDto dto = new CredentialOfferMetadataDto(true, "integrity", null, null);
        CredentialOfferMetadata metadata = CredentialOfferMapper.toCredentialOfferMetadataDto(dto);
        assertNotNull(metadata);
        assertEquals(true, metadata.deferred());
        assertEquals("integrity", metadata.vctIntegrity());
    }

    @Test
    void toCredentialOfferMetadata_returnsDefaultIfInputNull() {
        CredentialOfferMetadataDto result = CredentialOfferMapper.toCredentialOfferMetadata(null);
        assertNotNull(result);
        assertNull(result.deferred());
        assertNull(result.vctIntegrity());
    }

    @Test
    void toCredentialOfferMetadata_mapsFieldsCorrectly() {
        CredentialOfferMetadata metadata = new CredentialOfferMetadata(false, "vct#test", null, null);
        CredentialOfferMetadataDto dto = CredentialOfferMapper.toCredentialOfferMetadata(metadata);
        assertNotNull(dto);
        assertEquals(false, dto.deferred());
        assertEquals("vct#test", dto.vctIntegrity());
    }

    private CredentialOffer getCredentialOffer(CredentialOfferMetadata deferred, CredentialManagement mgmt) {
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getCredentialStatus()).thenReturn(CredentialStatusType.OFFERED);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("id1"));
        when(offer.getCredentialMetadata()).thenReturn(deferred);
        when(offer.getHolderJWKs()).thenReturn(List.of("jwk1", "jwk2"));
        when(offer.getClientAgentInfo()).thenReturn(new ClientAgentInfo("ip", "ua", "lang", "enc"));
        Instant now = Instant.now();
        when(offer.getOfferExpirationTimestamp()).thenReturn(now.getEpochSecond());
        when(offer.getCredentialValidFrom()).thenReturn(now);
        when(offer.getCredentialValidUntil()).thenReturn(now);
        when(offer.getCredentialRequest()).thenReturn(null);
        when(offer.getCredentialManagement()).thenReturn(mgmt);
        return offer;
    }
}