package ch.admin.bit.eid.issuer_management.controllers;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.models.dto.CreateCredentialRequestDto;
import ch.admin.bit.eid.issuer_management.models.dto.CredentialWithDeeplinkResponseDto;
import ch.admin.bit.eid.issuer_management.models.dto.StatusResponseDto;
import ch.admin.bit.eid.issuer_management.models.dto.UpdateStatusResponseDto;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import ch.admin.bit.eid.issuer_management.models.mappers.CredentialOfferMapper;
import ch.admin.bit.eid.issuer_management.services.CredentialService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

import static ch.admin.bit.eid.issuer_management.models.mappers.CredentialOfferMapper.credentialToCredentialResponseDto;
import static ch.admin.bit.eid.issuer_management.models.mappers.CredentialOfferMapper.credentialToUpdateStatusResponseDto;
import static ch.admin.bit.eid.issuer_management.models.mappers.StatusResponseMapper.credentialToStatusResponseDto;

@RestController
@RequestMapping(value = "/credentials")
@AllArgsConstructor
@Tag(name = "Credential API")
public class CredentialsController {

    private final CredentialService credentialService;

    @PostMapping("")
    @Operation(summary = "Create a generic credential offer with the given content",
            description = """
            Create a new credential offer, which can the be collected by the holder.
            The returned deep link has to be provided to the holder via an other channel, for example as QR-Code.
            The credentialSubjectData can be a json object or a JWT, if the signer has been configured to perform data integrity checks.
            Returns both the ID used to interact with the offer and later issued VC, and the deep link to be provided to
            """
            )
    public CredentialWithDeeplinkResponseDto createCredential(
            @Valid @RequestBody CreateCredentialRequestDto requestDto) {
        CredentialOffer credential = this.credentialService.createCredential(requestDto);

        String offerLinkString = this.credentialService.getOfferDeeplinkFromCredential(credential);

        return CredentialOfferMapper.credentialToCredentialResponseDto(credential, offerLinkString);
    }

    @GetMapping("/{credentialId}")
    @Operation(summary = "Get the offer data, if any is still cached")
    public Object getCredentialOffer(@PathVariable UUID credentialId) {
        return credentialToCredentialResponseDto(this.credentialService.getCredential(credentialId));
    }

    @GetMapping("/{credentialId}/offer_deeplink")
    @Operation(summary = "Get the offer deeplink")
    public String getCredentialOfferDeeplink(@PathVariable UUID credentialId) {
        CredentialOffer credential = this.credentialService.getCredential(credentialId);

        return this.credentialService.getOfferDeeplinkFromCredential(credential);
    }

    @GetMapping("/{credentialId}/status")
    @Operation(summary = "Get the current status of an offer or the verifiable credential, if already issued.")
    public StatusResponseDto getCredentialStatus(@PathVariable UUID credentialId) {
        CredentialOffer credential = this.credentialService.getCredential(credentialId);

        return credentialToStatusResponseDto(credential);
    }

    @PatchMapping("/{credentialId}/status")
    @Operation(summary = "Set the status of an offer or the verifiable credential associated with the id.")
    public UpdateStatusResponseDto updateCredentialStatus(@PathVariable UUID credentialId,
                                                          @RequestParam("credentialStatus") CredentialStatusEnum credentialStatus) {

        CredentialOffer credential = this.credentialService.updateCredentialStatus(credentialId, credentialStatus);

        return credentialToUpdateStatusResponseDto(credential);
    }
}
