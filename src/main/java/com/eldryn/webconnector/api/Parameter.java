package com.eldryn.webconnector.api;

import java.math.BigDecimal;
import java.util.*;
import java.util.regex.Pattern;

/** Scalar parameter schema, shared by Java and HTTP actions. */
public record Parameter(Type type, boolean required, int maxLength, Long minimum, Long maximum,
                        Set<String> allowed, String regex) {
    public enum Type { STRING, INTEGER, BOOLEAN, UUID, PLAYER_NAME, ENUM, REGEX }
    public Parameter {
        Objects.requireNonNull(type);
        allowed = Set.copyOf(allowed);
        if (maxLength < 1 || maxLength > 8192) throw new IllegalArgumentException("Invalid parameter length");
        if (minimum != null && maximum != null && minimum > maximum) throw new IllegalArgumentException("Invalid parameter range");
        if (type == Type.ENUM && allowed.isEmpty()) throw new IllegalArgumentException("Enum requires allowed values");
        if (type == Type.REGEX) { Objects.requireNonNull(regex); Pattern.compile(regex); }
    }
    public static Parameter required(Type type) { return new Parameter(type, true, 256, null, null, Set.of(), null); }
    public static Parameter enumeration(String... values) { return new Parameter(Type.ENUM, true, 256, null, null, Set.of(values), null); }
    public Object validate(Object value) {
        if (value == null) {
            if (required) throw new IllegalArgumentException("Missing required parameter");
            return null;
        }
        if (type == Type.INTEGER) {
            if (!(value instanceof Number)) throw new IllegalArgumentException("Expected integer");
            try {
                long n = new BigDecimal(value.toString()).longValueExact();
                if ((minimum != null && n < minimum) || (maximum != null && n > maximum)) throw new ArithmeticException();
                return n;
            } catch (ArithmeticException | NumberFormatException e) { throw new IllegalArgumentException("Integer outside allowed range"); }
        }
        if (type == Type.BOOLEAN) {
            if (!(value instanceof Boolean)) throw new IllegalArgumentException("Expected boolean");
            return value;
        }
        if (!(value instanceof String s) || s.length() > maxLength || s.codePoints().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("Invalid string");
        boolean valid = switch (type) {
            case PLAYER_NAME -> s.matches("[A-Za-z0-9_]{1,16}");
            case UUID -> s.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
            case ENUM -> allowed.contains(s);
            case REGEX -> Pattern.matches(regex, s);
            default -> true;
        };
        if (!valid) throw new IllegalArgumentException("Parameter does not match its schema");
        return s;
    }
}
