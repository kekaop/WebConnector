package com.eldryn.webconnector.config;

import java.util.*;
import java.util.regex.*;

public final class CommandTemplate {
    private static final Pattern TOKEN = Pattern.compile("\\{([A-Za-z_][A-Za-z0-9_]*)}");
    private CommandTemplate() { }
    public static void validate(String template, Set<String> parameters) {
        if (template.isBlank() || template.codePoints().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("Empty or multiline command template");
        Matcher m = TOKEN.matcher(template);
        while (m.find()) if (!m.group(1).equals("action") && !parameters.contains(m.group(1))) throw new IllegalArgumentException("Command placeholder requires a validation rule: " + m.group(1));
    }
    public static String render(String template, String action, Map<String, Object> payload) {
        Matcher matcher = TOKEN.matcher(template); StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            Object value = matcher.group(1).equals("action") ? action : payload.get(matcher.group(1));
            if (value == null || !String.valueOf(value).matches("[A-Za-z0-9_.:-]{1,256}")) throw new IllegalArgumentException("Unsafe or missing command token");
            matcher.appendReplacement(result, Matcher.quoteReplacement(String.valueOf(value)));
        }
        matcher.appendTail(result); return result.toString();
    }
}
