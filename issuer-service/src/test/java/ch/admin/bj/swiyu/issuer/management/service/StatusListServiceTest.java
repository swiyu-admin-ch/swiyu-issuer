package ch.admin.bj.swiyu.issuer.management.service;

import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.api.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListConfigDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.SignatureService;
import ch.admin.bj.swiyu.issuer.service.StatusListService;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import java.text.ParseException;
import java.util.*;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class StatusListServiceTest {
    private StatusListService statusListService;
    private ApplicationProperties applicationProperties;
    private StatusListProperties statusListProperties;
    private StatusRegistryClient statusRegistryClient;
    private StatusListRepository statusListRepository;
    private TransactionTemplate transaction;
    private SignatureService signatureService;
    private ECKey ecKey;
    private JWSSigner signer;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;

    private UUID statusRegistryEntryId = UUID.randomUUID();

    @BeforeEach
    void setUp() throws JOSEException, KeyStrategyException {
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        when(applicationProperties.getIssuerId()).thenReturn("did:example:mock");
        statusListProperties = Mockito.mock(StatusListProperties.class);
        when(statusListProperties.getVerificationMethod()).thenReturn("did:example:mock#key1");
        statusRegistryClient = Mockito.mock(StatusRegistryClient.class);
        when(statusRegistryClient.createStatusListEntry()).thenReturn(new StatusListEntryCreationDto()
                .id(statusRegistryEntryId)
                .statusRegistryUrl("https://www.example.com/" + statusRegistryEntryId));

        statusListRepository = Mockito.mock(StatusListRepository.class);
        when(statusListRepository.save(Mockito.any())).thenAnswer(invocation -> invocation.getArgument(0));
        transaction = Mockito.mock(TransactionTemplate.class);
        when(transaction.execute(Mockito.any())).then(invocation -> {
            TransactionCallback<StatusList> callback = invocation.getArgument(0);
            return callback.doInTransaction(null);
        });
        signatureService = Mockito.mock(SignatureService.class);
        ecKey = new ECKeyGenerator(Curve.P_256).keyID("did:example:mock#key1").generate();
        signer = new ECDSASigner(ecKey);
        when(signatureService.createSigner(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(signer);
        credentialOfferStatusRepository = Mockito.mock(CredentialOfferStatusRepository.class);
        when(credentialOfferStatusRepository.countByStatusListId(Mockito.any())).thenReturn(0);
        statusListService = new StatusListService(applicationProperties, statusListProperties, statusRegistryClient, statusListRepository, transaction, signatureService, credentialOfferStatusRepository);
        when(statusListProperties.getStatusListSizeLimit()).thenReturn(1000);
    }

    @ParameterizedTest
    @CsvSource({",", ",did:example:mock#overridekey1", "did:example:override,did:example:override#key1"})
    void whenTokenStatusListIsCreated_thenSuccess(String overrideDid, String overrideVerificationMethod) throws ParseException, JOSEException {
        var expectedIssuer = StringUtils.getIfBlank(overrideDid, applicationProperties::getIssuerId);
        var expectedVerificationMethod = StringUtils.getIfBlank(overrideVerificationMethod, statusListProperties::getVerificationMethod);
        StatusListCreateDto request = StatusListCreateDto.builder()
                .type(StatusListTypeDto.TOKEN_STATUS_LIST)
                .maxLength(10)
                .config(StatusListConfigDto.builder().bits(2).build())
                .configurationOverride(new ConfigurationOverrideDto(overrideDid, overrideVerificationMethod, null, null))
                .build();
        var statusListCaptor = ArgumentCaptor.forClass(StatusList.class);
        var jwtCaptor = ArgumentCaptor.forClass(String.class);
        statusListService.createStatusList(request);
        verify(statusRegistryClient).updateStatusListEntry(statusListCaptor.capture(), jwtCaptor.capture());
        var jwt = jwtCaptor.getValue();
        var parsedJwt = SignedJWT.parse(jwt);
        assertTrue(parsedJwt.verify(new ECDSAVerifier(ecKey.toECPublicKey())));
        assertEquals(expectedIssuer, parsedJwt.getJWTClaimsSet().getIssuer());
        assertEquals(expectedVerificationMethod, parsedJwt.getHeader().getKeyID());
    }

    @Test
    void revoke_shouldReturnStatusListId() {
        UUID statusListId = UUID.randomUUID();

        // create a valid token status zipped payload
        var token = new TokenStatusListToken(8, 10);

        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();

        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));

        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(1);

        List<UUID> result = statusListService.revoke(Set.of(offerStatus));

        assertEquals(1, result.size());
        assertEquals(statusListId, result.get(0));
    }

    @Test
    void suspend_shouldReturnStatusListId() {
        UUID statusListId = UUID.randomUUID();

        TokenStatusListToken token = new TokenStatusListToken(8, 10);

        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();

        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));

        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(2);

        List<UUID> result = statusListService.suspend(Set.of(offerStatus));

        assertEquals(1, result.size());
        assertEquals(statusListId, result.getFirst());
    }

    @Test
    void revalidate_shouldReturnStatusListId() {
        UUID statusListId = UUID.randomUUID();

        TokenStatusListToken token = new TokenStatusListToken(8, 10);

        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .configurationOverride(null)
                .build();

        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));

        CredentialOfferStatus offerStatus = Mockito.mock(CredentialOfferStatus.class);
        CredentialOfferStatusKey id = Mockito.mock(CredentialOfferStatusKey.class);
        when(offerStatus.getId()).thenReturn(id);
        when(id.getStatusListId()).thenReturn(statusListId);
        when(id.getIndex()).thenReturn(3);

        List<UUID> result = statusListService.revalidate(Set.of(offerStatus));

        assertEquals(1, result.size());
        assertEquals(statusListId, result.getFirst());
    }

    @Test
    void getStatusListInformation_whenExists_shouldReturnDtoAndCallCount() {
        UUID statusListId = UUID.randomUUID();
        StatusList statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .maxLength(10)
                .type(StatusListType.TOKEN_STATUS_LIST)
                .build();

        when(statusListRepository.findById(statusListId)).thenReturn(Optional.of(statusList));
        when(credentialOfferStatusRepository.countByStatusListId(statusListId)).thenReturn(3);
        when(statusListProperties.getVersion()).thenReturn("v1");

        var dto = statusListService.getStatusListInformation(statusListId);

        assertEquals(statusList.getUri(), dto.getStatusRegistryUrl());
        // verify repository interactions
        verify(statusListRepository, times(1)).findById(statusListId);
        verify(credentialOfferStatusRepository, times(1)).countByStatusListId(statusListId);
    }

    @Test
    void getStatusListInformation_whenNotFound_shouldThrow() {
        UUID statusListId = UUID.randomUUID();
        when(statusListRepository.findById(statusListId)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> statusListService.getStatusListInformation(statusListId));

        verify(statusListRepository, times(1)).findById(statusListId);
        verifyNoInteractions(credentialOfferStatusRepository);
    }
}