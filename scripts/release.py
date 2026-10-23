#!/usr/bin/env python3
"""Publicação por gh, npm e mcp-publisher com autenticação prévia."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
REPO = "daanielcruz/gsearch-mcp"
NPM_REGISTRY = "https://registry.npmjs.org"
MCP_REGISTRY = "https://registry.modelcontextprotocol.io"
PLATFORMS = ("darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64")
CHANNELS = ("github", "npm", "mcp")


class ReleaseError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def run(*args, cwd=ROOT, env=None, binary=False):
    # Never relay subprocess output: auth tools may include credentials in errors.
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True)
    require(result.returncode == 0, f"{Path(args[0]).name} {args[1] if len(args) > 1 else ''} failed (exit {result.returncode}); inspect the tool separately")
    return result.stdout if binary else result.stdout.decode().strip()


def tool(name):
    path = shutil.which(name)
    require(path, f"Required tool unavailable: {name}; install/authenticate separately")
    return path


def load(path):
    return json.loads(path.read_text())


def sha(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def names():
    return [f"gsearch-{kind}-{platform}" + (".exe" if platform.startswith("windows") else "")
            for kind in ("server", "installer") for platform in PLATFORMS]


def manifests():
    package, server = load(ROOT / "npm/package.json"), load(ROOT / "server.json")
    version = package["version"]
    require(re.fullmatch(r"\d+\.\d+\.\d+", version), "Release version must be stable X.Y.Z")
    require(server["version"] == version, "server.json version mismatch")
    require(package["mcpName"] == server["name"], "MCP namespace mismatch")
    require(any(p["registryType"] == "npm" and p["identifier"] == package["name"] for p in server["packages"]), "npm/MCP package mismatch")
    require(all(p["version"] == version for p in server["packages"]), "MCP package version mismatch")
    for directory in (".claude-plugin", ".cursor-plugin", ".codex-plugin", ".agents/plugins"):
        for filename in ("plugin.json", "marketplace.json"):
            path = ROOT / directory / filename
            if path.exists():
                data = load(path)
                entries = data.get("plugins", [data])
                if filename == "plugin.json":
                    require(data.get("version") == version, f"Version mismatch: {directory}/{filename}")
                    entry = data.get("mcpServers", {}).get("gsearch", {})
                    require(entry.get("command") == "npx" and entry.get("args") == ["-y", f"{package['name']}@{version}"], f"MCP package pin mismatch: {directory}/{filename}")
                else:
                    require(all(p.get("version", version) == version for p in entries), f"Version mismatch: {directory}/{filename}")
    server_go = (ROOT / "cmd/server/main.go").read_text()
    match = re.search(r'NewMCPServer\(\s*"gsearch",\s*"([^"]+)"', server_go)
    require(match and match[1] == version, "Go server version mismatch")
    installer = (ROOT / "cmd/installer/main.go").read_text()
    displays = re.findall(r'"v(\d+\.\d+\.\d+)"', installer)
    require(displays and all(v == version for v in displays), "Go installer version mismatch")
    bootstrap = (ROOT / "install.sh").read_text()
    launcher = (ROOT / "npm/bin/run.js").read_text()
    require('gsearch-server-${platform}-${arch}${ext}' in launcher, "npm binary naming contract changed")
    require('${name}-${PLATFORM}${SUFFIX}' in bootstrap, "install.sh binary naming contract changed")
    require(f'"{REPO}"' in launcher and f'"{REPO}"' in bootstrap, "Download repository mismatch")
    return version, package, server


def git_state(clean=False, tag=None):
    commit = run("git", "rev-parse", "HEAD")
    dirty = bool(run("git", "status", "--porcelain", "--untracked-files=normal"))
    if clean:
        require(not dirty, "Publishing requires a clean git worktree (including untracked files)")
    if tag:
        origin = run("git", "remote", "get-url", "origin")
        require(origin in (f"https://github.com/{REPO}", f"https://github.com/{REPO}.git", f"git@github.com:{REPO}.git"), "origin must be the public release repository")
        require(run("git", "rev-parse", f"refs/tags/{tag}^{{commit}}") == commit, "Release tag must point to HEAD")
        refs = run("git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
        remote = dict(line.split()[::-1] for line in refs.splitlines())
        require(remote.get(f"refs/tags/{tag}^{{}}", remote.get(f"refs/tags/{tag}")) == commit, "Push the matching release tag to origin first")
    return commit, dirty


def artifact_paths(directory, package, version):
    tarball = package["name"].lstrip("@").replace("/", "-") + f"-{version}.tgz"
    return [directory / name for name in names() + [tarball]]


def build(args, version, package):
    tool("go")
    tool("npm")
    commit, dirty = git_state()
    directory = args.dist / f"v{version}"
    require(not directory.exists(), "Versioned artifact directory already exists; preserving it (choose another --dist)")
    print(f"Build v{version}: {len(names())} binaries, npm tarball, SHA256SUMS, source provenance")
    if args.dry_run:
        for name in names():
            print(f"  would build {name}")
        print("DRY RUN: no artifacts written")
        return
    directory.mkdir(parents=True)
    for kind in ("server", "installer"):
        for platform in PLATFORMS:
            goos, goarch = platform.split("-")
            filename = f"gsearch-{kind}-{platform}" + (".exe" if goos == "windows" else "")
            env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0")
            run("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", str(directory / filename), f"./cmd/{kind}/", env=env)
            if args.codesign and goos == "darwin":
                run("codesign", "-s", "-", str(directory / filename))
            print(f"  built {filename}")
    packed = json.loads(run("npm", "pack", str(ROOT / "npm"), "--ignore-scripts", "--json", "--pack-destination", str(directory)))
    allowed = {"package.json", "bin/run.js", "README.md", "LICENSE"}
    require(len(packed) == 1 and all(f["path"] in allowed for f in packed[0]["files"]), "Unexpected npm package files; artifacts preserved, do not publish")
    paths = artifact_paths(directory, package, version)
    require(all(p.is_file() for p in paths), "Artifact filenames differ from installer/npm contracts")
    (directory / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.name}\n" for p in paths))
    (directory / "source.json").write_text(json.dumps({"version": version, "commit": commit, "dirty": dirty}, indent=2) + "\n")
    print(f"Built {len(names())} binaries; existing artifacts were not removed or overwritten")


def verify_artifacts(args, version, package, commit):
    directory = args.dist / f"v{version}"
    require(load(directory / "source.json") == {"version": version, "commit": commit, "dirty": False}, "Rebuild from clean tagged source into a fresh --dist directory")
    paths = artifact_paths(directory, package, version)
    expected = "".join(f"{sha(p)}  {p.name}\n" for p in paths)
    require((directory / "SHA256SUMS").read_text() == expected, "Artifact checksum mismatch")
    return paths + [directory / "SHA256SUMS"]


def get_json(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise ReleaseError(f"Registry read failed (HTTP {error.code}); no publication attempted") from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise ReleaseError("Registry read failed; no publication attempted") from None


def github(args, version, package, server, assets, verify_only=False):
    tool("gh")
    run("gh", "auth", "status")
    tag = f"v{version}"
    # Listing succeeds or fails explicitly; network/auth errors are never treated as absence.
    releases = json.loads(run("gh", "api", "--paginate", "--slurp", f"repos/{REPO}/releases?per_page=100"))
    existing = next((r for page in releases for r in page if r["tag_name"] == tag), None)
    if existing:
        require(not existing["draft"] and not existing["prerelease"], "Existing release is draft/prerelease; resolve manually")
        remote_assets = json.loads(run("gh", "api", "--paginate", "--slurp", f"repos/{REPO}/releases/{existing['id']}/assets?per_page=100"))
        remote_assets = {a["name"]: a for page in remote_assets for a in page}
        missing = []
        for path in assets:
            asset = remote_assets.get(path.name)
            if asset is None:
                missing.append(path)
                continue
            digest = asset.get("digest")
            if not digest:
                data = run("gh", "api", f"repos/{REPO}/releases/assets/{asset['id']}", "-H", "Accept: application/octet-stream", binary=True)
                digest = "sha256:" + hashlib.sha256(data).hexdigest()
            require(digest == "sha256:" + sha(path), "Existing GitHub asset differs; refusing overwrite")
        require(not (verify_only and missing), "GitHub assets not visible after upload; retry verification later")
        if missing and not args.dry_run:
            run("gh", "release", "upload", tag, *(str(p) for p in missing), "--repo", REPO)
            return github(args, version, package, server, assets, verify_only=True)
        print(f"github: {'would upload' if args.dry_run else 'missing'} {len(missing)} assets; existing assets verified")
    else:
        require(not verify_only, "GitHub release not visible after create; retry verification later")
        if not args.dry_run:
            run("gh", "release", "create", tag, *(str(p) for p in assets), "--repo", REPO, "--verify-tag", "--title", tag, "--generate-notes")
            return github(args, version, package, server, assets, verify_only=True)
        print(f"github: would create release with {len(assets)} verified assets")


def npm(args, version, package, server, assets, verify_only=False):
    tool("npm")
    run("npm", "whoami", "--registry", NPM_REGISTRY)
    tarball = next(p for p in assets if p.suffix == ".tgz")
    url = f"{NPM_REGISTRY}/{urllib.parse.quote(package['name'], safe='')}/{version}"
    existing = get_json(url)
    if existing is not None:
        with tarball.open("rb") as stream:
            digest = hashlib.sha1(stream.read()).hexdigest()
        require(existing.get("name") == package["name"] and existing.get("version") == version and existing.get("dist", {}).get("shasum") == digest, "Existing npm version differs from local tarball")
        print("npm: exact version and tarball digest verified; skipped")
    elif args.dry_run:
        print("npm: would publish verified tarball with public access")
    else:
        require(not verify_only, "npm version not visible after publish; retry verification later")
        run("npm", "publish", str(tarball), "--access", "public", "--ignore-scripts", "--registry", NPM_REGISTRY)
        npm(args, version, package, server, assets, verify_only=True)


def registry_normalize(value):
    # The registry omits optional false flags from its Go JSON response.
    if isinstance(value, dict):
        return {k: registry_normalize(v) for k, v in value.items()
                if not (k in ("isRequired", "isSecret") and v is False)}
    if isinstance(value, list):
        return [registry_normalize(v) for v in value]
    return value


def mcp(args, version, package, server, assets, verify_only=False):
    publisher = str(ROOT / "mcp-publisher") if (ROOT / "mcp-publisher").is_file() else tool("mcp-publisher")
    url = f"{MCP_REGISTRY}/v0.1/servers/{urllib.parse.quote(server['name'], safe='')}/versions/{version}"
    existing = get_json(url)
    if existing is not None:
        published = existing.get("server", {})
        require(all(registry_normalize(published.get(k)) == registry_normalize(v) for k, v in server.items() if k != "$schema"), "Existing MCP version differs from server.json")
        print("mcp: exact version and manifest verified; skipped")
        return
    # Modern publisher has no auth-status command (status edits lifecycle state).
    # Read only the documented token store; never print token data or change auth.
    token_path = Path.home() / ".config/mcp-publisher/token.json"
    require(token_path.is_file(), "MCP publisher needs existing authentication in its documented token store; authenticate separately")
    token = load(token_path)
    require(token.get("token") and token.get("registry", MCP_REGISTRY).rstrip("/") == MCP_REGISTRY, "MCP authentication missing or targets another registry; resolve separately")
    if args.dry_run:
        print("mcp: would publish server.json using existing authentication")
    else:
        require(not verify_only, "MCP version not visible after publish; retry verification later")
        run(publisher, "publish", str(ROOT / "server.json"))
        mcp(args, version, package, server, assets, verify_only=True)


def main():
    parser = argparse.ArgumentParser(description="Check/build/publish a release without implicit login, git writes, overwrites or deletion. Dry-run performs reads only, including registry/auth checks for publish.")
    parser.add_argument("command", choices=("check", "build", "publish"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--channel", choices=("all",) + CHANNELS, default="all", help="resume one channel independently")
    parser.add_argument("--dist", type=Path, default=ROOT / "dist", help="artifact parent; build refuses an existing vX.Y.Z directory")
    parser.add_argument("--codesign", action="store_true", help="ad-hoc sign Darwin binaries before checksums (macOS only)")
    args = parser.parse_args()
    args.dist = args.dist.resolve()
    version, package, server = manifests()
    print(f"Version consistency and installer/npm naming contracts: v{version} OK")
    if args.command == "check":
        _, dirty = git_state()
        print("Worktree: " + ("dirty (publication blocked)" if dirty else "clean"))
    elif args.command == "build":
        build(args, version, package)
    else:
        commit, _ = git_state(clean=True, tag=f"v{version}")
        assets = verify_artifacts(args, version, package, commit)
        failed = []
        selected = CHANNELS if args.channel == "all" else (args.channel,)
        for channel in selected:
            try:
                globals()[channel](args, version, package, server, assets)
                print(f"{channel}: {'DRY-RUN OK (not published)' if args.dry_run else 'VERIFIED'}")
            except (ReleaseError, OSError, ValueError, KeyError) as error:
                # Avoid untrusted exception strings (paths, registry bodies, tokens).
                message = str(error) if isinstance(error, ReleaseError) else type(error).__name__
                print(f"{channel}: FAILED — {message}", file=sys.stderr)
                failed.append(channel)
        require(not failed, "Partial/failed release; retry --channel " + ", ".join(failed) + "; no rollback or overwrite attempted")
        print("Dry-run complete; nothing published" if args.dry_run else "Selected channels verified: " + ", ".join(selected))


if __name__ == "__main__":
    try:
        main()
    except (ReleaseError, OSError, ValueError, KeyError) as error:
        message = str(error) if isinstance(error, ReleaseError) else type(error).__name__
        print(f"Release blocked: {message}", file=sys.stderr)
        sys.exit(1)
