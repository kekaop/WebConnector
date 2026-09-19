"""Run the example plugin and HTTP probes on an isolated Paper server. Python 3.10+, standard library only."""
import argparse
import hashlib
import json
import pathlib
import queue
import secrets
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zipfile


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paper", required=True, type=pathlib.Path)
    parser.add_argument("--java", default="java")
    parser.add_argument("--directory", required=True, type=pathlib.Path)
    parser.add_argument("--accept-eula", action="store_true", help="Accept https://aka.ms/MinecraftEULA for this test server")
    args = parser.parse_args()
    if not args.accept_eula:
        parser.error("Read the Minecraft EULA and explicitly pass --accept-eula to launch the test server")
    directory = args.directory.resolve()
    if directory.exists() and any(directory.iterdir()):
        parser.error("Test directory must be empty; use a new directory for each run")
    repo = pathlib.Path(__file__).resolve().parents[2]
    plugin = repo / "build/libs/WebConnector-2.0.0.jar"
    example = repo / "build/libs/WebConnectorExample-2.0.0.jar"
    if not plugin.is_file() or not example.is_file():
        parser.error("Run gradlew build first")
    directory.mkdir(parents=True, exist_ok=True)
    plugins = directory / "plugins"
    plugins.mkdir()
    shutil.copy2(args.paper.resolve(), directory / "paper.jar")
    shutil.copy2(plugin, plugins / plugin.name)
    shutil.copy2(example, plugins / example.name)
    (directory / "eula.txt").write_text("eula=true\n", encoding="utf-8")
    game_port, api_port = free_port(), free_port()
    (directory / "server.properties").write_text(
        f"server-ip=127.0.0.1\nserver-port={game_port}\nonline-mode=true\nview-distance=2\nsimulation-distance=2\n"
        "enable-query=false\nenable-rcon=false\nlevel-name=smoke-world\nlevel-type=minecraft:flat\n"
        "spawn-protection=0\nmax-players=1\n", encoding="utf-8")
    secret = secrets.token_hex(32)
    with zipfile.ZipFile(plugin) as jar:
        config = jar.read("config.yml").decode("utf-8")
    config = config.replace('port: 25575', f'port: {api_port}').replace('shared-secret: ""', f'shared-secret: "{secret}"')
    config = config.replace("shared-secret-actions: [ping]", "shared-secret-actions: [ping, example.echo]")
    data = plugins / "WebConnector"
    data.mkdir()
    (data / "config.yml").write_text(config, encoding="utf-8")
    lines = queue.Queue()
    process = subprocess.Popen([args.java, "-Xms512M", "-Xmx1G", "-jar", "paper.jar", "--nogui"], cwd=directory,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    transcript = []

    def consume():
        for line in process.stdout:
            transcript.append(line)
            lines.put(line)

    threading.Thread(target=consume, daemon=True).start()

    def call(path, body=None, key=None):
        headers = {"X-Shared-Secret": secret, "Content-Type": "application/json"}
        if key:
            headers["Idempotency-Key"] = key
        request = urllib.request.Request(f"http://127.0.0.1:{api_port}/api/{path}",
                                         data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            return response.code, json.load(response)

    try:
        deadline = time.monotonic() + 240
        ready = False
        while time.monotonic() < deadline and process.poll() is None:
            try:
                if 'Done (' in lines.get(timeout=1):
                    ready = True
                    break
            except queue.Empty:
                pass
        if not ready:
            raise RuntimeError("Paper did not become ready; inspect server.log")
        assert call("ping", {})[0] == 200
        first = call("example.echo", {"player": "Steve"}, "smoke-order")
        second = call("example.echo", {"player": "Steve"}, "smoke-order")
        assert first[0] == second[0] == 200, (first, second)
        assert first[1]["operation_id"] == second[1]["operation_id"]
        assert first[1]["result"]["message"] == "Echo Steve (#1)"
        assert second[1]["replayed"] is True
        assert call("example.echo", {"player": "Alex"}, "smoke-order")[0] == 409
        assert call("example.echo", {"player": "@a"}, "bad-player")[0] == 400
        assert call("example.private", {})[0] == 404
        operation = call("operations/" + first[1]["operation_id"])
        assert operation[0] == 200 and operation[1]["operation"]["state"] == "COMPLETED"
        assert any("WebConnector Java API smoke test passed" in line for line in transcript)
        for command in ("webconnector status", "webconnector reload", "webconnector diagnostics"):
            process.stdin.write(command + "\n")
        process.stdin.flush()
        time.sleep(1)
        assert call("ping", {})[0] == 200
        report = {"passed": True, "plugin_sha256": hashlib.sha256(plugin.read_bytes()).hexdigest(),
                  "paper_sha256": hashlib.sha256(args.paper.read_bytes()).hexdigest(),
                  "checks": ["plugin enable", "ServicesManager API", "main-thread handler", "HTTP", "idempotency", "validation", "polling", "reload"]}
        (directory / "smoke-result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
    finally:
        if process.poll() is None:
            try:
                process.stdin.write("stop\n")
                process.stdin.flush()
                process.wait(timeout=40)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=10)
        (directory / "server.log").write_text("".join(transcript).replace(secret, "[redacted]"), encoding="utf-8")


if __name__ == "__main__":
    main()
