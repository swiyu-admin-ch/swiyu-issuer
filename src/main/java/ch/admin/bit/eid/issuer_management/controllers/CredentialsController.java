package ch.admin.bit.eid.issuer_management.controllers;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.models.dto.CreateCredentialRequestDto;
import ch.admin.bit.eid.issuer_management.models.dto.CredentialWithDeeplinkResponseDto;
import ch.admin.bit.eid.issuer_management.models.dto.UpdateStatusResponseDto;
import ch.admin.bit.eid.issuer_management.models.entities.CredentialOfferEntity;
import ch.admin.bit.eid.issuer_management.models.mappers.CredentialOfferMapper;
import ch.admin.bit.eid.issuer_management.services.CredentialService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

import static ch.admin.bit.eid.issuer_management.models.mappers.CredentialOfferMapper.credentialToCredentialResponseDto;
import static ch.admin.bit.eid.issuer_management.models.mappers.CredentialOfferMapper.credentialToUpdateStatusResponseDto;

// TODO add prefix
@RestController
@RequestMapping(value = "/credentials")
@AllArgsConstructor
public class CredentialsController {

    private final CredentialService credentialService;

    @PostMapping("")
    @Operation(summary = "Creates a generic credential offer with the given content")
    public CredentialWithDeeplinkResponseDto createCredential(
            @RequestBody CreateCredentialRequestDto requestDto) {
        CredentialOfferEntity credential = this.credentialService.createCredential(requestDto);

        String offerLinkString = this.credentialService.getOfferDeeplinkFromCredential(credential);

        return CredentialOfferMapper.credentialToCredentialResponseDto(credential, offerLinkString);
    }

    @GetMapping("/{credentialId}")
    @Operation(summary = "Gets the offer data, if any is still cached")
    public Object getCredentialOffer(@PathVariable UUID credentialId) {
        return credentialToCredentialResponseDto(this.credentialService.getCredential(credentialId));
    }

    @GetMapping("/{credentialId}/offer_deeplink")
    @Operation(summary = "Gets the offer deeplink")
    public String getCredentialOfferDeeplink(@PathVariable UUID credentialId) {
        CredentialOfferEntity credential = this.credentialService.getCredential(credentialId);

        return this.credentialService.getOfferDeeplinkFromCredential(credential);
    }

    @GetMapping("/{credentialId}/status")
    public String getCredentialStatus(@PathVariable UUID credentialId) {
        CredentialOfferEntity credential = this.credentialService.getCredential(credentialId);

        return credential.getCredentialStatus().getDisplayName();
    }

    @PatchMapping("/{credentialId}/status")
    public UpdateStatusResponseDto updateCredentialStatus(@PathVariable UUID credentialId,
                                                          @RequestParam("credentialStatus") CredentialStatusEnum credentialStatus) {

        CredentialOfferEntity credential = this.credentialService.updateCredentialStatus(credentialId, credentialStatus);

        return credentialToUpdateStatusResponseDto(credential);
    }
}
