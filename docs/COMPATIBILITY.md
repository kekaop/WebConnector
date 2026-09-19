# Compatibility

[Home](../README.md) · [Tests](TESTING.md)

WebConnector 2.x is compiled against the Bukkit/Spigot 1.20.1 API with Java 17 bytecode (`api-version: 1.20`). It uses no NMS, CraftBukkit internals or version-specific packet classes. Paper 1.20.1–26.2 is the target range; 26.3 support is experimental while upstream builds are in preview.

| Minecraft family | Server Java | Automated API test target |
| --- | --- | --- |
| 1.20.1–1.20.4 | 17 | 1.20.1 |
| 1.20.5–1.20.6 | 21 | 1.20.6 |
| 1.21–1.21.11 | 21 | 1.21.11 |
| 26.1–26.2 | 25 | 26.2 |
| 26.3 preview | 25 | 26.3 |

The [CI workflow](../.github/workflows/build.yml) runs the core, HTTP, security and webhook suites on Windows and Linux with these API/runtime combinations. This verifies common API linkage and HTTP behavior; it is not a live Paper boot test for every Minecraft patch release. A separate [Paper smoke test](TESTING.md#paper-smoke-test) verifies service registration and server-thread execution on a supplied server JAR. Third-party commands and Skript addon compatibility depend on those plugins' own releases.

Use the Java runtime required by the selected server build, even though the plugin bytecode is Java 17. Paper documents its current requirements in [Getting started](https://docs.papermc.io/paper/getting-started/). Preview server builds and compatible Paper forks require their own staging checks. Folia, Velocity/BungeeCord, Fabric and Forge are not supported platforms for this JAR.
