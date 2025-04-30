/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.oid4vci.api.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialRequest;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialResponseEncryption;
import ch.admin.bj.swiyu.issuer.oid4vci.service.mapper.CredentialRequestMapper;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static ch.admin.bj.swiyu.issuer.oid4vci.service.mapper.CredentialRequestMapper.toCredentialResponseEncryption;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CredentialRequestMapperTest {

    @Test
    void testToCredentialRequest() {
        // Arrange
        CredentialRequestDto dto = mock(CredentialRequestDto.class);
        when(dto.proof()).thenReturn(Map.of("key", "value"));
        when(dto.format()).thenReturn("vc+sd-jwt");
        when(dto.credentialResponseEncryption()).thenReturn(null);

        // Act
        CredentialRequest credentialRequest = CredentialRequestMapper.toCredentialRequest(dto);
        CredentialResponseEncryption credentialResponseEncryption = toCredentialResponseEncryption(dto.credentialResponseEncryption());

        // Assert
        assertEquals(dto.proof(), credentialRequest.getProof());
        assertEquals(dto.format(), credentialRequest.getFormat());
        assertEquals(credentialResponseEncryption, credentialRequest.getCredentialResponseEncryption());
    }
}