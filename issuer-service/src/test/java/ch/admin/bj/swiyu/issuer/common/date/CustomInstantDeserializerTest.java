package ch.admin.bj.swiyu.issuer.common.date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;

import java.io.IOException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CustomInstantDeserializerTest {

    private CustomInstantDeserializer deserializer;
    private JsonParser jsonParser;
    private DeserializationContext deserializationContext;

    @BeforeEach
    void setUp() {
        deserializer = new CustomInstantDeserializer();
        jsonParser = mock(JsonParser.class);
        deserializationContext = mock(DeserializationContext.class);
    }

    @Test
    void testDeserialize_withMilliseconds() throws IOException {
        String dateTimeWithMs = "2023-02-25T16:50:48.123Z";
        when(jsonParser.getString()).thenReturn(dateTimeWithMs);

        Instant expectedInstant = Instant.parse(dateTimeWithMs);
        Instant actualInstant = deserializer.deserialize(jsonParser, deserializationContext);

        assertEquals(expectedInstant, actualInstant);
    }

    @Test
    void testDeserialize_withoutMilliseconds() {
        String dateTimeWithoutMs = "2023-02-25T16:50:48Z";
        when(jsonParser.getString()).thenReturn(dateTimeWithoutMs);

        Instant expectedInstant = Instant.parse(dateTimeWithoutMs);
        Instant actualInstant = deserializer.deserialize(jsonParser, deserializationContext);

        assertEquals(expectedInstant, actualInstant);
    }

    @Test
    void testDeserialize_invalidFormat() {
        String invalidDateTime = "invalid-date-time";
        when(jsonParser.getString()).thenReturn(invalidDateTime);

        try {
            deserializer.deserialize(jsonParser, deserializationContext);
        } catch (Exception e) {
            assertEquals("Text 'invalid-date-time' could not be parsed at index 0", e.getMessage());
        }
    }
}