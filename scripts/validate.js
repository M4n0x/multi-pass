const fs = require("fs/promises");
const path = require("path");

const rootDir = path.resolve(__dirname, "..");
const baseManifestPath = path.join(rootDir, "manifests", "manifest.base.mv3.json");
const firefoxMv2ManifestPath = path.join(rootDir, "manifests", "manifest.firefox.mv2.json");
const devManifestPath = path.join(rootDir, "basic-auth-extension", "manifest.json");

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

async function main() {
  const [baseManifest, mv2Manifest, devManifest] = await Promise.all([
    readJson(baseManifestPath),
    readJson(firefoxMv2ManifestPath),
    readJson(devManifestPath)
  ]);

  const baseVersion = baseManifest.version;
  if (mv2Manifest.version !== baseVersion) {
    throw new Error(
      `Version mismatch: base=${baseVersion} firefox-mv2=${mv2Manifest.version}`
    );
  }
  if (devManifest.version !== baseVersion) {
    throw new Error(
      `Version mismatch: base=${baseVersion} dev=${devManifest.version}`
    );
  }

  console.log("Manifest validation passed.");
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
