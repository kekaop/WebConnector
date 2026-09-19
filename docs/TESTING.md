# Testing

[Home](../README.md)

Run `./gradlew build` (Windows: `gradlew.bat build`) with Java 17 or 21. The build compiles the public API consumer and runs unit/integration tests. Tests cover authentication, expiry, scopes, CIDRs, validation, command interpolation, rate limits, queue capacity, durable idempotency, concurrent retries, operation transitions, crash recovery, timeouts, dangerous-action exclusion, filesystem traversal/links/junctions, configuration migration rejection, real HTTP requests, webhook signatures/retries/filtering and live key/route replacement.

## API/runtime matrix

```powershell
./scripts/test-matrix.ps1 -Java17 'C:\Java\jdk-17' -Java21 'C:\Java\jdk-21' -Java25 'C:\Java\jdk-25'
```

Or run one target on any platform:

```sh
./gradlew test -PtestApi=26.2-R0.1-SNAPSHOT -PtestJavaHome=/path/to/jdk-25
```

Production classes always compile against 1.20.1 with release 17. The selected API and Java runtime apply to tests. Reports are in `build/reports/tests/test`; the PowerShell matrix copies each target's JUnit XML to `build/compatibility/`.

## Paper smoke test

The testbed contains WebConnector, a separate Java consumer plugin, an HTTP client/mock integration, and an optional signed webhook receiver. Use a fresh directory and a Paper JAR downloaded from the upstream project. The script never touches an existing server directory and requires explicit EULA acceptance before launch.

```sh
./gradlew build
python examples/testbed/run_smoke.py \
  --paper /path/to/paper.jar --java /path/to/java \
  --directory /path/to/new-empty-test-directory --accept-eula
```

Read [Minecraft EULA](https://aka.ms/MinecraftEULA) before passing that flag. The script binds Minecraft and the API to loopback, generates disposable credentials, starts Paper, checks plugin/API registration, main-thread handling, HTTP validation, idempotency, polling and reload, then stops it. It writes `smoke-result.json` with artifact hashes and `server.log` with the test secret redacted. Do not install `WebConnectorExample` on a production server.

The [mock webhook receiver](../examples/webhook_receiver.py) listens on loopback, verifies signatures and event timestamps, and deduplicates event IDs. Set `WEBCONNECTOR_WEBHOOK_SECRET`, run it, and point a test route to its `/webhook` endpoint. Real HTTP retry scenarios are also exercised automatically in JUnit using a temporary receiver.

For Skript, install one matching addon at a time and load the corresponding [example](../examples/skript/). Review the addon version constraints and known limitations in [Skript integration](SKRIPT.md). A source-checked syntax example is not evidence that a particular Skript/addon/server combination has booted successfully.
