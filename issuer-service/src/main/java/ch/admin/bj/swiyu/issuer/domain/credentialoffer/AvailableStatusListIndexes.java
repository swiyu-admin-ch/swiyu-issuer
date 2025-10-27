package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.Immutable;

import java.util.List;

/**
 * Database view to get indexes
 */
@Entity
@Immutable
@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor(access = AccessLevel.PROTECTED) // Builder
@Table(name = "available_status_list_indexes")
public class AvailableStatusListIndexes {
    @Id
    @Column(name = "status_list_uri")
    private String statusListUri;

    @Column(name = "free_indexes")
    private List<Integer> freeIndexes;
}
