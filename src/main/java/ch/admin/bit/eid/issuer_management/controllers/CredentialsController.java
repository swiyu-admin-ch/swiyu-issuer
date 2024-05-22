package ch.admin.bit.eid.issuer_management.controllers;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.exceptions.NotImplementedError;
import ch.admin.bit.eid.issuer_management.models.dto.CreateCredentialRequestDto;
import ch.admin.bit.eid.issuer_management.models.dto.CredentialWithDeeplinkResponseDto;
import ch.admin.bit.eid.issuer_management.models.entities.CredentialOfferEntity;
import ch.admin.bit.eid.issuer_management.models.mappers.CredentialOfferMapper;
import ch.admin.bit.eid.issuer_management.services.CredentialService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.AllArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

import static ch.admin.bit.eid.issuer_management.models.mappers.CredentialOfferMapper.credentialToCredentialResponseDto;

// TODO add prefix
@RestController
@RequestMapping(value = "/credentials")
@AllArgsConstructor
public class CredentialsController {

    private final CredentialService credentialService;

    @PostMapping("")
    @Operation(summary = "Creates a generic credential offer with the given content")
    public CredentialWithDeeplinkResponseDto createCredential(
            @Validated @RequestBody CreateCredentialRequestDto requestDto) {
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
    public void updateCredentialStatus(@PathVariable UUID credentialId) {
        /**
         *     management = load_management_object(credential_management_id, session)
         *     if db_credential.CredentialStatus.is_post_holder_interaction(management.credential_status):
         *         _update_credential_status_for_processed_vcs(
         *             session=session, config=config, key_conf=key_conf, management=management, credential_status=credential_status, purpose=purpose.lower()
         *         )
         *     elif db_credential.CredentialStatus.is_during_holder_interaction(management.credential_status):
         *         _reset_offer(management)
         *     else:
         *         _update_credential_status_for_unprocessed_vcs(management, credential_status)
         *
         *     session.commit()
         *     return VcManagementInfo.model_validate(management, from_attributes=True)
         */

        CredentialOfferEntity credential = this.credentialService.getCredential(credentialId);

        if (credential.getCredentialStatus().isPostHolderInteraction()) {
            /*
              _update_credential_status_for_processed_vcs(
            session=session, config=config, key_conf=key_conf, management=management, credential_status=credential_status, purpose=purpose.lower()
        )
             */
            throw new NotImplementedError();

        } else if (credential.getCredentialStatus().isDuringHolderInteraction()) {
            // TODO Check
            credential.setCredentialStatus(CredentialStatusEnum.OFFERED);
            throw new NotImplementedError();
        } else {
            throw new NotImplementedError();
        }
    }
}
