const fs = require("fs/promises");
const path = require("path");

const rootDir = path.resolve(__dirname, "..");
const baseManifestPath = path.join(rootDir, "manifests", "manifest.base.mv3.json");
const devManifestPath = path.join(rootDir, "basic-auth-extension", "manifest.json");

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

async function main() {
  const [baseManifest, devManifest] = await Promise.all([
    readJson(baseManifestPath),
    readJson(devManifestPath)
  ]);

  const baseVersion = baseManifest.version;
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
