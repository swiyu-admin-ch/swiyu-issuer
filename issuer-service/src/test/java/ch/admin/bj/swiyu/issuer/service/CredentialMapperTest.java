package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestErrorResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthErrorDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthErrorResponseDto;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialMapperTest {

    @Test
    void toOAuthErrorResponseDto_mapsAllErrors() {
        for (OAuthError error : OAuthError.values()) {
            OAuthException ex = new OAuthException(error, "msg");
            OAuthErrorResponseDto dto = CredentialMapper.toOAuthErrorResponseDto(ex);
            assertEquals(CredentialMapper.toOAuthErrorDto(error), dto.error());
            assertEquals("msg", dto.errorDescription());
        }
    }

    @Test
    void toOAuthErrorDto_mapsAllValues() {
        assertEquals(OAuthErrorDto.INVALID_REQUEST, CredentialMapper.toOAuthErrorDto(OAuthError.INVALID_REQUEST));
        assertEquals(OAuthErrorDto.INVALID_CLIENT, CredentialMapper.toOAuthErrorDto(OAuthError.INVALID_CLIENT));
        assertEquals(OAuthErrorDto.INVALID_GRANT, CredentialMapper.toOAuthErrorDto(OAuthError.INVALID_GRANT));
        assertEquals(OAuthErrorDto.INVALID_TOKEN, CredentialMapper.toOAuthErrorDto(OAuthError.INVALID_TOKEN));
        assertEquals(OAuthErrorDto.UNAUTHORIZED_CLIENT, CredentialMapper.toOAuthErrorDto(OAuthError.UNAUTHORIZED_CLIENT));
        assertEquals(OAuthErrorDto.UNSUPPORTED_GRANT_TYPE, CredentialMapper.toOAuthErrorDto(OAuthError.UNSUPPORTED_GRANT_TYPE));
        assertEquals(OAuthErrorDto.INVALID_SCOPE, CredentialMapper.toOAuthErrorDto(OAuthError.INVALID_SCOPE));
    }

    @Test
    void toCredentialRequestErrorResponseDto_mapsAllErrors() {
        for (CredentialRequestError error : CredentialRequestError.values()) {
            Oid4vcException ex = new Oid4vcException(error, "msg");
            CredentialRequestErrorResponseDto dto = CredentialMapper.toCredentialRequestErrorResponseDto(ex);
            assertEquals("msg", dto.errorDescription());
        }
    }
}