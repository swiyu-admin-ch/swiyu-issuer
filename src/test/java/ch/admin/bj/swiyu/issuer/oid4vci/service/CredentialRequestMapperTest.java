/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.service.mapper.CredentialRequestMapper;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.mapper.CredentialRequestMapper.toCredentialResponseEncryption;
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
        CredentialRequestClass credentialRequest = CredentialRequestMapper.toCredentialRequest(dto);
        CredentialResponseEncryptionClass credentialResponseEncryption = toCredentialResponseEncryption(dto.credentialResponseEncryption());

        // Assert
        assertEquals(dto.proof(), credentialRequest.getProof());
        assertEquals(dto.format(), credentialRequest.getFormat());
        assertEquals(credentialResponseEncryption, credentialRequest.getCredentialResponseEncryption());
    }
}