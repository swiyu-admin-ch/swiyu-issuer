package ch.admin.bj.swiyu.issuer.infrastructure.callback;

import com.fasterxml.jackson.annotation.JsonValue;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;

import java.time.Instant;
import java.util.UUID;
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
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
    @Enumerated(EnumType.STRING)
    private CallbackEventType type;

    @Column
    @CreatedDate
    private Instant createdAt;


}
