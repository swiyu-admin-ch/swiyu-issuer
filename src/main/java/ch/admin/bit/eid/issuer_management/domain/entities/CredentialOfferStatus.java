package ch.admin.bit.eid.issuer_management.domain.entities;

import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "credential_offer_status")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialOfferStatus {

    @EmbeddedId
    private CredentialOfferStatusKey id;

    @ManyToOne
    @MapsId("offerId")
    @JoinColumn(name = "credential_offer_id", referencedColumnName = "id")
    private CredentialOffer offer;

    @ManyToOne(fetch = FetchType.EAGER)
    @MapsId("statusListId")
    @JoinColumn(name = "status_list_id", referencedColumnName = "id")
    private StatusList statusList;

    private Integer index;

}
