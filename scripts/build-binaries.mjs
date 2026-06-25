/**
 * Build script for cross-platform standalone executables.
 *
 * Compiles the CLI tool into native binaries for distribution on Gumroad.
 * Users don't need Node.js — just download and run.
 *
 * Requirements:
 *   - Install Bun: https://bun.sh (curl -fsSL https://bun.sh/install | bash)
 *
 * Usage:
 *   node scripts/build-binaries.mjs           # Build for current platform
 *   node scripts/build-binaries.mjs --all      # Build for all platforms
 *   node scripts/build-binaries.mjs --win      # Build for Windows only
 *   node scripts/build-binaries.mjs --mac      # Build for macOS only
 *   node scripts/build-binaries.mjs --linux    # Build for Linux only
 *
 * Output: ./dist-binaries/
 */

import { execSync } from "child_process";
import { existsSync, mkdirSync, rmSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT_DIR = join(ROOT, "dist-binaries");
const ENTRY = join(ROOT, "src", "index.ts");
const PACKAGE_NAME = "env-secure";

const args = process.argv.slice(2);
const buildAll = args.includes("--all");
const buildWin = args.includes("--win") || buildAll;
const buildMac = args.includes("--mac") || buildAll;
const buildLinux = args.includes("--linux") || buildAll;

// If no platform specified, build for current platform
const buildCurrent = !buildWin && !buildMac && !buildLinux;

const targets = [];

if (buildCurrent) {
  const platform = process.platform;
  const arch = process.arch;
  const osMap = { win32: "windows", darwin: "macos", linux: "linux" };
  const archMap = { x64: "x64", arm64: "arm64" };
  targets.push({
    name: `${PACKAGE_NAME}-${osMap[platform] || platform}-${archMap[arch] || arch}`,
    target: `bun-${osMap[platform] || platform}-${archMap[arch] || arch}`,
  });
}

if (buildWin) {
  targets.push(
    { name: `${PACKAGE_NAME}-windows-x64`, target: "bun-windows-x64" },
  );
}

if (buildMac) {
  targets.push(
    { name: `${PACKAGE_NAME}-macos-arm64`, target: "bun-darwin-arm64" },
    { name: `${PACKAGE_NAME}-macos-x64`, target: "bun-darwin-x64" },
  );
}

if (buildLinux) {
  targets.push(
    { name: `${PACKAGE_NAME}-linux-x64`, target: "bun-linux-x64" },
    { name: `${PACKAGE_NAME}-linux-arm64`, target: "bun-linux-arm64" },
  );
}

// Clean output directory
if (existsSync(OUT_DIR)) {
  rmSync(OUT_DIR, { recursive: true });
}
mkdirSync(OUT_DIR, { recursive: true });

console.log(`\n  \u26a1 Compiling ${PACKAGE_NAME} to standalone binaries...\n`);

for (const { name, target } of targets) {
  const ext = target.includes("windows") ? ".exe" : "";
  const outPath = join(OUT_DIR, `${name}${ext}`);

  console.log(`  \ud83d\udce6 Building: ${name}`);

  try {
    execSync(
      `bun build --compile --target=${target} --outfile="${outPath}" "${ENTRY}"`,
      {
        cwd: ROOT,
        stdio: "pipe",
        timeout: 120_000, // 2 minutes
      }
    );

    const size = statSync(outPath).size;
    const sizeMB = (size / 1024 / 1024).toFixed(1);
    console.log(`     \u2705 ${sizeMB} MB \u2192 ${outPath}`);
  } catch (err) {
    console.error(`     \u274c Failed: ${err.message}`);
  }
}

console.log(`\n  \ud83d\udcc2 Output directory: ${OUT_DIR}`);
console.log(`  \ud83d\udce6 ${targets.length} binary(ies) built\n`);
