package com.eldryn.webconnector.core;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.StringReader;
import java.math.BigDecimal;
import java.util.*;

public final class Json {
    public static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private Json() { }
    /** Strict JSON objects with bounded depth; rejects duplicate keys and trailing input. */
    public static Map<String, Object> object(String text) {
        try (JsonReader reader = new JsonReader(new StringReader(text.isBlank() ? "{}" : text))) {
            reader.setLenient(false);
            Object value = read(reader, 0);
            if (!(value instanceof Map<?, ?>) || reader.peek() != JsonToken.END_DOCUMENT) throw new IllegalArgumentException();
            @SuppressWarnings("unchecked") Map<String, Object> map = (Map<String, Object>) value;
            return map;
        } catch (Exception e) { throw new IllegalArgumentException("Expected a valid JSON object"); }
    }
    private static Object read(JsonReader reader, int depth) throws Exception {
        if (depth > 16) throw new IllegalArgumentException();
        return switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                Map<String, Object> values = new LinkedHashMap<>(); reader.beginObject();
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    if (values.containsKey(key) || values.size() >= 256) throw new IllegalArgumentException();
                    values.put(key, read(reader, depth + 1));
                }
                reader.endObject(); yield values;
            }
            case BEGIN_ARRAY -> {
                List<Object> values = new ArrayList<>(); reader.beginArray();
                while (reader.hasNext()) { if (values.size() >= 1024) throw new IllegalArgumentException(); values.add(read(reader, depth + 1)); }
                reader.endArray(); yield values;
            }
            case STRING -> reader.nextString();
            case NUMBER -> new BigDecimal(reader.nextString());
            case BOOLEAN -> reader.nextBoolean();
            case NULL -> { reader.nextNull(); yield null; }
            default -> throw new IllegalArgumentException();
        };
    }
    public static String canonical(Map<String, Object> payload) { return GSON.toJson(new TreeMap<>(payload)); }
}
