package ch.admin.bj.swiyu.issuer.service.test;

import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class TestServiceUtils {

    public static String createHolderProof(JWK holderPrivateKey, String issuerUri, String nonce, String proofTypeString) throws JOSEException {
        return createHolderProof(holderPrivateKey, issuerUri, nonce, proofTypeString, Date.from(Instant.now()));
    }

    public static String createAttestedHolderProof(
            JWK holderPrivateKey,
            String issuerUri,
            String nonce,
            String proofTypeString,
            AttackPotentialResistance attestationLevel,
            String attestationIssuerDid) throws JOSEException {
        return createHolderProofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, Date.from(Instant.now()), attestationLevel, attestationIssuerDid, holderPrivateKey);
    }

    public static String createAttestedHolderProof(
            JWK holderPrivateKey,
            String issuerUri,
            String nonce,
            String proofTypeString,
            AttackPotentialResistance attestationLevel,
            String attestationIssuerDid,
            JWK attestationKey) throws JOSEException {
        return createHolderProofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, Date.from(Instant.now()), attestationLevel, attestationIssuerDid, attestationKey);
    }

    public static String createHolderProof(JWK holderPrivateKey, String issuerUri, String nonce, String proofTypeString, Date issueTime) throws JOSEException {
        return createHolderProofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, issueTime, null, null, holderPrivateKey);
    }

    public static String createKeyAttestationJwt(JWK attestationKey, JWK holderPrivateKey, AttackPotentialResistance attestationLevel, String attestationIssuerDid) throws JOSEException {

        var attestationSigner = prepareSigner(attestationKey);
        attestationIssuerDid = attestationIssuerDid == null ? "did:webvh:scid:test-attestation-builder" : attestationIssuerDid;

        JWSHeader header = new JWSHeader.Builder(attestationSigner.alg)
                .type(new JOSEObjectType("key-attestation+jwt"))
                .keyID(attestationIssuerDid + "#" + (attestationKey.getKeyID() == null ? "key-1" : attestationKey.getKeyID()))
                .customParam(SwissProfileVersions.PROFILE_VERSION_PARAM, SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(attestationIssuerDid)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("key_storage", List.of(attestationLevel.getValue()))
                .claim("attested_keys", List.of(holderPrivateKey.toPublicJWK().toJSONObject()))
                .build();
        var attestation = new SignedJWT(header, claims);
        attestation.sign(attestationSigner.signer);
        return attestation.serialize();
    }

    @NotNull
    private static String createHolderProofJWT(
            JWK holderPrivateKey,
            String issuerUri,
            String nonce,
            String proofTypeString,
            Date issueTime,
            @Nullable AttackPotentialResistance attestationLevel,
            @Nullable String attestationIssuerDid,
            JWK attestationKey) throws JOSEException {
        var holderSignerSupport = assertDoesNotThrow(() -> prepareSigner(holderPrivateKey));
        JWSSigner signer = holderSignerSupport.signer;

        var headerBuilder = new JWSHeader.Builder(holderSignerSupport.alg)
                .type(new JOSEObjectType(proofTypeString));
        headerBuilder.jwk(holderPrivateKey.toPublicJWK());
        // Add attestation if required
        if (attestationLevel != null) {
            headerBuilder.customParam("key_attestation", createKeyAttestationJwt(attestationKey, holderPrivateKey, attestationLevel, attestationIssuerDid));
        }
        JWSHeader header = headerBuilder
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", issuerUri)
                .issueTime(issueTime)
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt.serialize();
    }

    public static CredentialManagement getCredentialManagement(CredentialStatusManagementType status, UUID accessToken) {
        return CredentialManagement.builder()
                .credentialManagementStatus(status)
                .accessToken(accessToken)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .build();
    }

    public static CredentialOffer getCredentialOffer(CredentialOfferStatusType status, long offerExpirationTimestamp, Map<String, Object> offerData, UUID preAuthorizedCode, CredentialOfferMetadata offerMetadata, UUID transactionId) {
        return CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(status)
                .metadataCredentialSupportedId(List.of("test"))
                .offerData(offerData)
                .credentialMetadata(offerMetadata)
                .transactionId(transactionId)
                .preAuthorizedCode(preAuthorizedCode)
                .offerExpirationTimestamp(offerExpirationTimestamp)
                .deferredOfferValiditySeconds(120)
                .credentialValidFrom(Instant.now())
                .credentialValidUntil(Instant.now().plusSeconds(200))
                .credentialRequest(new CredentialRequestClass("vc+sd-jwt", null, null))
                .build();
    }

    public static SignerSupport prepareSigner(JWK jwk) throws JOSEException {
        JWSSigner signer = null;
        JWSAlgorithm algorithm = JWSAlgorithm.ES256;
        if (jwk.getAlgorithm() == null || JWSAlgorithm.Family.EC.contains(jwk.getAlgorithm())) {
            signer = new ECDSASigner(jwk.toECKey());
        } else if (JWSAlgorithm.Ed25519.equals(jwk.getAlgorithm())) {
            signer = new Ed25519Signer(jwk.toOctetKeyPair());
            algorithm = JWSAlgorithm.Ed25519;
        }
        return new SignerSupport(signer, algorithm);
    }

    public record SignerSupport(JWSSigner signer, JWSAlgorithm alg) {
    }
}