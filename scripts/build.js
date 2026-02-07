const fs = require("fs/promises");
const path = require("path");
const { execSync } = require("child_process");

const rootDir = path.resolve(__dirname, "..");
const sourceDir = path.join(rootDir, "basic-auth-extension");
const distDir = path.join(rootDir, "dist");
const manifestDir = path.join(rootDir, "manifests");

const targets = [
  {
    name: "chromium",
    manifestBase: "manifest.base.mv3.json",
    manifestOverride: "manifest.chromium.json",
    outputDir: "chromium",
    zipBase: "multipass-chromium"
  },
  {
    name: "firefox-mv3",
    manifestBase: "manifest.base.mv3.json",
    manifestOverride: "manifest.firefox.mv3.json",
    outputDir: "firefox-mv3",
    zipBase: "multipass-firefox-mv3"
  }
];

function isObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function deepMerge(base, override) {
  if (!isObject(base)) {
    return override;
  }
  const merged = { ...base };
  for (const [key, value] of Object.entries(override || {})) {
    if (value === null) {
      delete merged[key];
      continue;
    }
    if (isObject(value) && isObject(merged[key])) {
      merged[key] = deepMerge(merged[key], value);
    } else if (value !== undefined) {
      merged[key] = value;
    }
  }
  return merged;
}

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

async function copyExtension(targetDir) {
  await fs.rm(targetDir, { recursive: true, force: true });
  await fs.mkdir(targetDir, { recursive: true });
  await fs.cp(sourceDir, targetDir, { recursive: true });
}

async function pruneLegacyArtifacts(targetDir) {
  await fs.rm(path.join(targetDir, "background-mv2.js"), { force: true });
}

async function writeManifest(targetDir, manifest) {
  const manifestPath = path.join(targetDir, "manifest.json");
  await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

function zipTarget(targetDir, zipName) {
  const zipPath = path.join(distDir, zipName);
  execSync(`zip -r "${zipPath}" .`, { stdio: "inherit", cwd: targetDir });
}

async function buildTarget(target) {
  const targetDir = path.join(distDir, target.outputDir);
  await copyExtension(targetDir);
  await pruneLegacyArtifacts(targetDir);

  const overridePath = path.join(manifestDir, target.manifestOverride);
  const overrideManifest = await readJson(overridePath);
  let manifest = overrideManifest;

  if (target.manifestBase) {
    const basePath = path.join(manifestDir, target.manifestBase);
    const baseManifest = await readJson(basePath);
    manifest = deepMerge(baseManifest, overrideManifest);
  }

  await writeManifest(targetDir, manifest);
  const version = manifest.version;
  const zipName = `${target.zipBase}-v${version}.zip`;
  zipTarget(targetDir, zipName);
}

async function main() {
  await fs.rm(distDir, { recursive: true, force: true });
  await fs.mkdir(distDir, { recursive: true });

  for (const target of targets) {
    await buildTarget(target);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
