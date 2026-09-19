package com.eldryn.webconnector;

import com.eldryn.webconnector.api.*;
import com.eldryn.webconnector.config.*;
import com.eldryn.webconnector.core.*;
import com.eldryn.webconnector.events.*;
import com.eldryn.webconnector.http.*;
import org.bukkit.*;
import org.bukkit.command.*;
import org.bukkit.event.*;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.ServicePriority;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.configuration.file.YamlConfiguration;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;

public final class WebConnectorPlugin extends JavaPlugin implements Listener, TabExecutor {
    private PluginSettings settings;
    private ActionService actions;
    private HttpGateway gateway;
    private WebhookDispatcher webhooks;
    private Listener eventListener;
    @Override public void onEnable() {
        try {
            boolean firstStart = !getDataFolder().toPath().resolve("config.yml").toFile().exists();
            saveDefaultConfig();
            if (firstStart) {
                byte[] secret = new byte[32]; new SecureRandom().nextBytes(secret);
                getConfig().set("security.shared-secret", HexFormat.of().formatHex(secret)); saveConfig();
                getLogger().info("Generated API secret in config.yml. Keep this file private.");
            }
            settings = readSettings();
            webhooks = new WebhookDispatcher(settings.serverName(), settings.webhookCapacity(), settings.webhookAttempts(),
                    Duration.ofSeconds(settings.webhookTimeout()), settings.webhookBackoff(), getLogger());
            OperationStore store = new OperationStore(getDataFolder().toPath().resolve("operations"), settings.journalCapacity());
            actions = new ActionService(store, new ActionService.Scheduler() {
                public void onMainThread(Runnable task) { Bukkit.getScheduler().runTask(WebConnectorPlugin.this, task); }
                public boolean isMainThread() { return Bukkit.isPrimaryThread(); }
            }, settings.workerThreads(), settings.actionQueue(), settings.keyLimit(), settings.actionLimit(), getLogger(), webhooks::publish);
            actions.replaceConfigured(compileActions(settings));
            eventListener = EventBridge.register(this, webhooks, settings.bindings());
            webhooks.routes(settings.routes());
            gateway = new HttpGateway(actions, settings.security(), settings.http()); gateway.start();
            Bukkit.getServicesManager().register(WebConnectorAPI.class, actions, this, ServicePriority.Normal);
            Bukkit.getPluginManager().registerEvents(this, this);
            Objects.requireNonNull(getCommand("webconnector")).setExecutor(this);
            Objects.requireNonNull(getCommand("webconnector")).setTabCompleter(this);
            getLogger().info("HTTP API listening on " + settings.http().host() + ":" + gateway.port() + settings.http().path());
        } catch (Exception e) {
            getLogger().severe("WebConnector could not start. Check config-version, authentication, action schemas, journal integrity and port availability. See docs/TROUBLESHOOTING.md.");
            if (e.getMessage() != null && e.getMessage().startsWith("Configuration version 2 is required.")) getLogger().severe(e.getMessage());
            Bukkit.getPluginManager().disablePlugin(this);
        }
    }
    private PluginSettings readSettings() throws Exception {
        YamlConfiguration yaml = new YamlConfiguration(); yaml.load(getDataFolder().toPath().resolve("config.yml").toFile()); return PluginSettings.read(yaml);
    }
    private List<ActionDefinition> compileActions(PluginSettings candidate) throws Exception {
        FileGuard files = new FileGuard(Path.of("."), candidate.fileRoots(), List.of(getDataFolder().toPath(), getFile().toPath()), candidate.deleteEnabled());
        List<ActionDefinition> definitions = new ArrayList<>();
        for (PluginSettings.ConfiguredAction a : candidate.actions()) {
            for (String file : a.files()) files.validate(file);
            definitions.add(a.builder().handler(context -> {
                // Validate every substitution and file before the first side effect.
                List<String> commands = a.commands().stream().map(c -> CommandTemplate.render(c, context.action(), context.payload())).toList();
                for (String file : a.files()) files.validate(file);
                for (String command : commands) {
                    context.checkDeadline();
                    if (!Bukkit.dispatchCommand(Bukkit.getConsoleSender(), command)) return ActionResult.failure("command_failed", "A configured command was not accepted; earlier commands may have completed");
                }
                for (String file : a.files()) { context.checkDeadline(); files.delete(file); }
                if (a.shutdown()) { context.checkDeadline(); Bukkit.getScheduler().runTaskLater(this, Bukkit::shutdown, a.shutdownDelay()); }
                return ActionResult.success();
            }).build());
        }
        return definitions;
    }
    private void reloadConnector() throws Exception {
        PluginSettings candidate = readSettings();
        if (!settings.sameRuntime(candidate)) throw new IllegalArgumentException("Listener, worker, journal and delivery settings require a server restart");
        List<ActionDefinition> definitions = compileActions(candidate);
        Listener replacement = EventBridge.register(this, webhooks, candidate.bindings());
        try { actions.replaceConfigured(definitions); }
        catch (Exception e) { HandlerList.unregisterAll(replacement); throw e; }
        if (eventListener != null) HandlerList.unregisterAll(eventListener);
        eventListener = replacement; webhooks.routes(candidate.routes()); gateway.security(candidate.security()); settings = candidate;
    }
    @Override public void onDisable() {
        Bukkit.getServicesManager().unregisterAll(this);
        if (gateway != null) gateway.close();
        if (webhooks != null) webhooks.close();
        if (actions != null) try { actions.close(); } catch (Exception e) { getLogger().severe("Operation journal could not be closed cleanly; check storage before restart"); }
        if (eventListener != null) HandlerList.unregisterAll(eventListener);
    }
    @EventHandler public void onJoin(PlayerJoinEvent event) {
        if (!event.getPlayer().hasPlayedBefore()) Bukkit.getPluginManager().callEvent(new PlayerFirstJoinEvent(event.getPlayer()));
    }
    private boolean allowed(CommandSender sender, String permission) { return sender.hasPermission("webconnector.admin") || sender.hasPermission(permission); }
    @Override public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String sub = args.length == 0 ? "status" : args[0].toLowerCase(Locale.ROOT);
        String permission = switch (sub) { case "reload" -> "webconnector.reload"; case "test" -> "webconnector.execute"; case "diagnostics" -> "webconnector.diagnostics"; default -> "webconnector.status"; };
        if (!allowed(sender, permission)) { sender.sendMessage("You do not have permission to use this command."); return true; }
        try {
            switch (sub) {
                case "status" -> sender.sendMessage("WebConnector " + getDescription().getVersion() + " | HTTP port " + gateway.port() + " | actions " + actions.getActions().size() + " | healthy " + actions.healthy());
                case "reload" -> { reloadConnector(); sender.sendMessage("Actions, keys and event routes reloaded."); }
                case "actions" -> sender.sendMessage("Actions: " + String.join(", ", actions.getActions().stream().map(ActionDefinition::name).toList()));
                case "action" -> {
                    if (args.length < 2) throw new IllegalArgumentException("Usage: /webconnector action <name>");
                    ActionDefinition a = actions.getAction(args[1]).orElseThrow(() -> new IllegalArgumentException("Unknown action"));
                    sender.sendMessage(a.name() + ": " + a.description() + " | HTTP=" + a.exposeHttp() + " dangerous=" + a.dangerous() + " parameters=" + a.parameters().keySet());
                }
                case "operations" -> {
                    if (args.length > 1) sender.sendMessage(actions.getOperation(UUID.fromString(args[1])).map(o -> o.id() + " " + o.action() + " " + o.state() + " request=" + o.requestId()).orElse("Operation not found"));
                    else actions.getOperations().stream().sorted(Comparator.comparing(OperationStatus::createdAt).reversed()).limit(10).forEach(o -> sender.sendMessage(o.id() + " " + o.action() + " " + o.state()));
                }
                case "test" -> {
                    if (args.length < 2) throw new IllegalArgumentException("Usage: /webconnector test <action> [JSON] [--key=<id>]. This executes the action.");
                    ActionDefinition a = actions.getAction(args[1]).orElseThrow(() -> new IllegalArgumentException("Unknown action"));
                    String key = args[args.length - 1].startsWith("--key=") ? args[args.length - 1].substring(6) : null;
                    int end = key == null ? args.length : args.length - 1;
                    Map<String, Object> payload = Json.object(end > 2 ? String.join(" ", Arrays.copyOfRange(args, 2, end)) : "{}");
                    boolean console = sender instanceof ConsoleCommandSender;
                    Set<String> permissions = a.permission().isEmpty() || sender.hasPermission(a.permission()) ? Set.of(a.permission()) : Set.of();
                    Caller caller = new Caller("command:" + (sender instanceof org.bukkit.entity.Player p ? p.getUniqueId() : sender.getName()), Set.of(a.name()), console ? Set.of("*") : permissions,
                            console || sender.hasPermission("webconnector.dangerous"), false);
                    Submission submission = actions.submit(a.name(), payload, caller, key);
                    sender.sendMessage("Operation " + submission.operationId() + " submitted. Use /webconnector operations " + submission.operationId());
                }
                case "events" -> { sender.sendMessage("Event routes: " + String.join(", ", webhooks.routes().stream().map(WebhookDispatcher.Route::name).toList())); sender.sendMessage("Delivery: " + webhooks.statistics()); }
                case "diagnostics" -> { sender.sendMessage("Java " + System.getProperty("java.version") + " | Bukkit " + Bukkit.getBukkitVersion()); sender.sendMessage("Service=" + actions.healthy() + " | journal records=" + actions.getOperations().size() + " | webhooks=" + webhooks.statistics()); }
                default -> sender.sendMessage("Usage: /webconnector <status|reload|actions|action|operations|test|events|diagnostics>");
            }
        } catch (ActionException e) { sender.sendMessage(e.code() + ": " + e.getMessage()); }
        catch (IllegalArgumentException e) { sender.sendMessage(sub.equals("reload") ? "Reload rejected. Check config version, keys, schemas and restart-only settings; active configuration retained." : e instanceof java.util.regex.PatternSyntaxException ? "Invalid validation pattern" : e.getMessage()); }
        catch (Exception e) { sender.sendMessage("Configuration reload failed; the active configuration is retained. Check the file and documentation."); }
        return true;
    }
    @Override public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (!allowed(sender, "webconnector.status")) return List.of();
        if (args.length == 1) return List.of("status", "reload", "actions", "action", "operations", "test", "events", "diagnostics").stream().filter(s -> s.startsWith(args[0])).toList();
        if (args.length == 2 && Set.of("action", "test").contains(args[0])) return actions.getActions().stream().map(ActionDefinition::name).filter(s -> s.startsWith(args[1])).toList();
        return List.of();
    }
}
