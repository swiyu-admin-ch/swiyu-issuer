package ch.admin.bj.swiyu.issuer.management.service;

import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.api.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListConfigDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.SignatureService;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListService;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListSigningService;
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
import org.junit.jupiter.api.Assertions;
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
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    private StatusListSigningService signingService;

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

        signingService = new StatusListSigningService(applicationProperties, statusListProperties, signatureService);

        statusListService = new StatusListService(
                applicationProperties,
                statusListProperties,
                statusRegistryClient,
                signingService,
                statusListRepository,
                transaction,
                credentialOfferStatusRepository);

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

    /**
     * Happy path: all requested status list URIs can be resolved and are returned.
     */
    @Test
    void resolveAndValidateStatusLists_shouldReturnListsWhenAllResolved() {
        var uri1 = "https://example.com/status1";
        var uri2 = "https://example.com/status2";
        var statusList1 = StatusList.builder().uri(uri1).build();
        var statusList2 = StatusList.builder().uri(uri2).build();

        var request = CreateCredentialOfferRequestDto.builder()
                .statusLists(List.of(uri1, uri2))
                .build();

        when(statusListRepository.findByUriIn(List.of(uri1, uri2)))
                .thenReturn(List.of(statusList1, statusList2));

        var result = statusListService.resolveAndValidateStatusLists(request);

        assertEquals(List.of(statusList1, statusList2), result);
        verify(statusListRepository).findByUriIn(List.of(uri1, uri2));
        verifyNoMoreInteractions(statusListRepository);
    }

    /**
     * Exception path: if not all provided URIs can be resolved, the method must fail and include
     * the resolved URIs in the error message.
     */
    @Test
    void resolveAndValidateStatusLists_shouldThrowWhenNotAllResolved() {
        var uri1 = "https://example.com/status1";
        var uri2 = "https://example.com/status2";
        var statusList1 = StatusList.builder().uri(uri1).build();

        var request = CreateCredentialOfferRequestDto.builder()
                .statusLists(List.of(uri1, uri2))
                .build();

        when(statusListRepository.findByUriIn(List.of(uri1, uri2)))
                .thenReturn(List.of(statusList1)); // Only one resolved

        var ex = Assertions.assertThrows(BadRequestException.class,
                () -> statusListService.resolveAndValidateStatusLists(request));

        assertTrue(ex.getMessage().contains(uri1));
        assertFalse(ex.getMessage().contains(uri2));
    }

    /**
     * Edge case: an empty list of status lists should be considered valid and results in an empty resolution.
     */
    @Test
    void resolveAndValidateStatusLists_shouldReturnEmptyWhenRequestIsEmpty() {
        var request = CreateCredentialOfferRequestDto.builder()
                .statusLists(List.of())
                .build();

        when(statusListRepository.findByUriIn(List.of())).thenReturn(List.of());

        var result = statusListService.resolveAndValidateStatusLists(request);

        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(statusListRepository).findByUriIn(List.of());
        verifyNoMoreInteractions(statusListRepository);
    }

    /**
     * Happy path: updating to {@link CredentialStatusManagementType#REVOKED} should mark entries as revoked.
     */
    @Test
    void updateStatusListsForPostIssuance_shouldRevokeWhenStatusIsRevoked() {
        var statusListId = UUID.randomUUID();
        var token = new TokenStatusListToken(8, 10);

        var statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .build();

        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));

        var offerStatus = CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(statusListId)
                        .index(1)
                        .build())
                .build();

        var result = statusListService.updateStatusListsForPostIssuance(Set.of(offerStatus), CredentialStatusManagementType.REVOKED);

        assertEquals(List.of(statusListId), result);
        verify(statusListRepository, atLeastOnce()).findByIdForUpdate(statusListId);
    }

    /**
     * Happy path: updating to {@link CredentialStatusManagementType#SUSPENDED} should mark entries as suspended.
     */
    @Test
    void updateStatusListsForPostIssuance_shouldSuspendWhenStatusIsSuspended() {
        var statusListId = UUID.randomUUID();
        var token = new TokenStatusListToken(8, 10);

        var statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .build();

        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));

        var offerStatus = CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(statusListId)
                        .index(2)
                        .build())
                .build();

        var result = statusListService.updateStatusListsForPostIssuance(Set.of(offerStatus), CredentialStatusManagementType.SUSPENDED);

        assertEquals(List.of(statusListId), result);
        verify(statusListRepository, atLeastOnce()).findByIdForUpdate(statusListId);
    }

    /**
     * Happy path: updating to {@link CredentialStatusManagementType#ISSUED} should re-validate entries.
     */
    @Test
    void updateStatusListsForPostIssuance_shouldRevalidateWhenStatusIsIssued() {
        var statusListId = UUID.randomUUID();
        var token = new TokenStatusListToken(8, 10);

        var statusList = StatusList.builder()
                .id(statusListId)
                .uri("https://example.com/" + statusListId)
                .config(Map.of("bits", 8))
                .statusZipped(token.getStatusListData())
                .maxLength(10)
                .build();

        when(statusListRepository.findByIdForUpdate(statusListId)).thenReturn(Optional.of(statusList));

        var offerStatus = CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(statusListId)
                        .index(3)
                        .build())
                .build();

        var result = statusListService.updateStatusListsForPostIssuance(Set.of(offerStatus), CredentialStatusManagementType.ISSUED);

        assertEquals(List.of(statusListId), result);
        verify(statusListRepository, atLeastOnce()).findByIdForUpdate(statusListId);
    }

    @Test
    void updateStatusListsForPostIssuance_shouldThrowWhenNoStatusListsFound() {
        var ex = Assertions.assertThrows(BadRequestException.class,
                () -> statusListService.updateStatusListsForPostIssuance(Set.of(), CredentialStatusManagementType.REVOKED));

        assertTrue(ex.getMessage().toLowerCase(Locale.ROOT).contains("no associated status lists"));
    }

    @Test
    void updateStatusListsForPostIssuance_shouldThrowForInvalidTransition() {
        var offerStatus = CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(UUID.randomUUID())
                        .index(1)
                        .build())
                .build();

        var ex = Assertions.assertThrows(BadRequestException.class,
                () -> statusListService.updateStatusListsForPostIssuance(Set.of(offerStatus), CredentialStatusManagementType.INIT));

        assertTrue(ex.getMessage().contains("Illegal state transition"));
    }

}

