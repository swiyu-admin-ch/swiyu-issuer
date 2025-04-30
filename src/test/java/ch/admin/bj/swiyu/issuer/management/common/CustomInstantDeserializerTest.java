package ch.admin.bj.swiyu.issuer.management.common;

import ch.admin.bj.swiyu.issuer.management.common.date.CustomInstantDeserializer;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CustomInstantDeserializerTest {

    private CustomInstantDeserializer deserializer;
    private JsonParser jsonParser;
    private DeserializationContext deserializationContext;

    @BeforeEach
    public void setUp() {
        deserializer = new CustomInstantDeserializer();
        jsonParser = mock(JsonParser.class);
        deserializationContext = mock(DeserializationContext.class);
    }

    @Test
    public void testDeserialize_withMilliseconds() throws IOException {
        String dateTimeWithMs = "2023-02-25T16:50:48.123Z";
        when(jsonParser.getText()).thenReturn(dateTimeWithMs);

        Instant expectedInstant = Instant.parse(dateTimeWithMs);
        Instant actualInstant = deserializer.deserialize(jsonParser, deserializationContext);

        assertEquals(expectedInstant, actualInstant);
    }

    @Test
    public void testDeserialize_withoutMilliseconds() throws IOException {
        String dateTimeWithoutMs = "2023-02-25T16:50:48Z";
        when(jsonParser.getText()).thenReturn(dateTimeWithoutMs);

        Instant expectedInstant = Instant.parse(dateTimeWithoutMs);
        Instant actualInstant = deserializer.deserialize(jsonParser, deserializationContext);

        assertEquals(expectedInstant, actualInstant);
    }

    @Test
    public void testDeserialize_invalidFormat() throws IOException {
        String invalidDateTime = "invalid-date-time";
        when(jsonParser.getText()).thenReturn(invalidDateTime);

        try {
            deserializer.deserialize(jsonParser, deserializationContext);
        } catch (Exception e) {
            assertEquals("Text 'invalid-date-time' could not be parsed at index 0", e.getMessage());
        }
    }
}
