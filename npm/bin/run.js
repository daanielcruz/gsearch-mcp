#!/usr/bin/env node

const { existsSync, mkdirSync, chmodSync, createWriteStream } = require("fs");
const { join } = require("path");
const { spawn } = require("child_process");
const https = require("https");

const VERSION = "1.0.1";
const REPO = "daanielcruz/gsearch-mcp";
const BIN_DIR = join(__dirname, "..", ".bin-cache");

const PLATFORM_MAP = { darwin: "darwin", linux: "linux", win32: "windows" };
const ARCH_MAP = { arm64: "arm64", x64: "amd64" };

function getBinaryName() {
  const platform = PLATFORM_MAP[process.platform];
  const arch = ARCH_MAP[process.arch];
  if (!platform || !arch) {
    console.error(`Unsupported platform: ${process.platform}-${process.arch}`);
    process.exit(1);
  }
  const ext = process.platform === "win32" ? ".exe" : "";
  return `gsearch-server-${platform}-${arch}${ext}`;
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const follow = (url) => {
      https.get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return follow(res.headers.location);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`Download failed: HTTP ${res.statusCode}`));
        }
        const file = createWriteStream(dest);
        res.pipe(file);
        file.on("finish", () => file.close(resolve));
        file.on("error", reject);
      }).on("error", reject);
    };
    follow(url);
  });
}

async function ensureBinary() {
  const name = getBinaryName();
  const binPath = join(BIN_DIR, name);

  if (existsSync(binPath)) return binPath;

  mkdirSync(BIN_DIR, { recursive: true });

  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${name}`;
  process.stderr.write(`Downloading gsearch-server v${VERSION}...\n`);

  await download(url, binPath);

  if (process.platform !== "win32") {
    chmodSync(binPath, 0o755);
  }

  process.stderr.write("Done.\n");
  return binPath;
}

async function main() {
  const binPath = await ensureBinary();
  const child = spawn(binPath, process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
  });
  child.on("exit", (code) => process.exit(code ?? 1));
  child.on("error", (err) => {
    console.error(`Failed to start gsearch-server: ${err.message}`);
    process.exit(1);
  });
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
