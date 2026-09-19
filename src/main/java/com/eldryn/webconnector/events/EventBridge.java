package com.eldryn.webconnector.events;

import com.eldryn.webconnector.config.PluginSettings.EventBinding;
import org.bukkit.Bukkit;
import org.bukkit.event.*;
import org.bukkit.plugin.Plugin;
import java.lang.reflect.Method;
import java.util.*;
import java.util.regex.*;

public final class EventBridge {
    private static final Pattern TOKEN = Pattern.compile("\\{event\\.([A-Za-z0-9_.]+)}");
    private EventBridge() { }
    public static Listener register(Plugin plugin, WebhookDispatcher dispatcher, List<EventBinding> bindings) {
        Listener listener = new Listener() { };
        try {
            for (EventBinding binding : bindings) {
                Class<? extends Event> event = resolve(binding.eventClass());
                Bukkit.getPluginManager().registerEvent(event, listener, EventPriority.valueOf(binding.priority().toUpperCase(Locale.ROOT)), (ignored, value) -> {
                    Map<String, Object> data = new LinkedHashMap<>();
                    binding.payload().forEach((k, template) -> data.put(k, render(value, template)));
                    dispatcher.publish(binding.type(), data, binding.route());
                }, plugin, binding.ignoreCancelled());
            }
            return listener;
        } catch (RuntimeException e) { HandlerList.unregisterAll(listener); throw e; }
    }
    public static Class<? extends Event> resolve(String name) {
        for (String prefix : List.of("", "com.eldryn.webconnector.", "org.bukkit.event.", "org.bukkit.event.player.", "org.bukkit.event.block.", "org.bukkit.event.entity.", "org.bukkit.event.inventory.", "org.bukkit.event.server.", "org.bukkit.event.world.", "io.papermc.paper.event.", "com.destroystokyo.paper.event.")) {
            try { return Class.forName(prefix + name).asSubclass(Event.class); }
            catch (ClassNotFoundException | ClassCastException ignored) { }
        }
        throw new IllegalArgumentException("Unknown event class: " + name);
    }
    public static String render(Event event, String template) {
        Matcher matcher = TOKEN.matcher(template); StringBuilder output = new StringBuilder();
        while (matcher.find()) matcher.appendReplacement(output, Matcher.quoteReplacement(read(event, matcher.group(1))));
        matcher.appendTail(output); return output.toString();
    }
    private static String read(Object object, String path) {
        String[] segments = path.split("\\."); if (segments.length > 8) return "";
        for (String segment : segments) {
            if (object == null || segment.equalsIgnoreCase("class") || segment.equalsIgnoreCase("getClass")) return "";
            Object next = null;
            for (Method method : object.getClass().getMethods()) {
                String name = method.getName();
                if (method.getParameterCount() != 0 || method.getReturnType() == void.class || !(name.startsWith("get") || name.startsWith("is"))) continue;
                String property = name.substring(name.startsWith("get") ? 3 : 2);
                if (property.equalsIgnoreCase(segment) || name.equalsIgnoreCase(segment)) {
                    try { next = method.invoke(object); } catch (Exception ignored) { }
                    break;
                }
            }
            object = next;
        }
        return object == null ? "" : String.valueOf(object);
    }
}
