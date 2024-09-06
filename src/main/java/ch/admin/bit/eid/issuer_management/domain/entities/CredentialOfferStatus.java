package ch.admin.bit.eid.issuer_management.domain.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "credential_offer_status")
public class CredentialOfferStatus {

    @Id
    @ManyToOne
    @JoinColumn(name = "credential_offer_id", referencedColumnName = "id")
    private CredentialOffer offer;

    @Id
    @ManyToOne
    @JoinColumn(name = "status_list_id", referencedColumnName = "id")
    private StatusListEntity statusList;

    private int index;
}
