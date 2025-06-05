package ch.admin.bj.swiyu.issuer.domain.callback;

import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;

import java.time.Instant;
import java.util.UUID;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PUBLIC) // JPA
@Table(name="callback_event")
public class CallbackEvent {

    @Id
    @Builder.Default
    private UUID id = UUID.randomUUID(); // Generate the ID manually

    /**
     * ID of the object the callback is about known to the receiver of the callback,
     * example id (aka management_id) of the credential_offer
     */
    @Column
    private UUID subjectId;

    /**
     * Event. Exact specification
     */
    @Column
    private String event;

    @Column
    @Nullable
    private String eventDescription;

    @Column
    @Enumerated(EnumType.STRING)
    private CallbackEventType type;

    @Column
    @CreatedDate
    private Instant timestamp;


}
