package ch.admin.bit.eid.issuer_management.domain.entities;

import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "credential_offer_status")
@Getter
@Setter
public class CredentialOfferStatus {

    @EmbeddedId
    private CredentialOfferStatusKey id;

    @ManyToOne
    @MapsId("offerId")
    @JoinColumn(name = "credential_offer_id", referencedColumnName = "id")
    private CredentialOffer offer;

    @ManyToOne
    @MapsId("statusListId")
    @JoinColumn(name = "status_list_id", referencedColumnName = "id")
    private StatusList statusList;

    private Integer index;

}
