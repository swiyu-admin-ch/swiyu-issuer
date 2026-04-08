package ch.admin.bj.swiyu.issuer.service.test;

import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class TestServiceUtils {

    public static String createHolderProof(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString) throws JOSEException {
        return createHolderProof(holderPrivateKey, issuerUri, nonce, proofTypeString, Date.from(Instant.now()));
    }

    public static String createAttestedHolderProof(
            ECKey holderPrivateKey,
            String issuerUri,
            String nonce,
            String proofTypeString,
            AttackPotentialResistance attestationLevel,
            String attestationIssuerDid) throws JOSEException {
        return createHolderProofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, Date.from(Instant.now()), attestationLevel, attestationIssuerDid, holderPrivateKey);
    }

    public static String createAttestedHolderProof(
            ECKey holderPrivateKey,
            String issuerUri,
            String nonce,
            String proofTypeString,
            AttackPotentialResistance attestationLevel,
            String attestationIssuerDid,
            ECKey attestationKey) throws JOSEException {
        return createHolderProofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, Date.from(Instant.now()), attestationLevel, attestationIssuerDid, attestationKey);
    }

    public static String createHolderProof(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, Date issueTime) throws JOSEException {
        return createHolderProofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, issueTime, null, null, holderPrivateKey);
    }

    @NotNull
    private static String createHolderProofJWT(
            ECKey holderPrivateKey,
            String issuerUri,
            String nonce,
            String proofTypeString,
            Date issueTime,
            @Nullable AttackPotentialResistance attestationLevel,
            @Nullable String attestationIssuerDid,
            ECKey attestationKey) throws JOSEException {
        JWSSigner signer = new ECDSASigner(holderPrivateKey);

        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(proofTypeString));
        headerBuilder.jwk(holderPrivateKey.toPublicJWK());
        // Add attestation if required
        if (attestationLevel != null) {
            JWSSigner attestationSigner = new ECDSASigner(attestationKey);
            var attestation = createKeyAttestation(attestationLevel, holderPrivateKey.toPublicJWK(), attestationIssuerDid == null ? "did:test:test-attestation-builder" : attestationIssuerDid);
            attestation.sign(attestationSigner);
            headerBuilder.customParam("key_attestation", attestation.serialize());
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

    private static SignedJWT createKeyAttestation(AttackPotentialResistance attestationLevel, ECKey publicJWK, String attestationIssuerDid) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("key-attestation+jwt"))
                .keyID(attestationIssuerDid + "#key-1")
                .customParam(SwissProfileVersions.PROFILE_VERSION_PARAM, SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(attestationIssuerDid)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("key_storage", List.of(attestationLevel.getValue()))
                .claim("attested_keys", List.of(publicJWK.toJSONObject()))
                .build();
        return new SignedJWT(header, claims);
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
}