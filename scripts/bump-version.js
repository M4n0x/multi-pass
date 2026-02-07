const fs = require("fs/promises");
const path = require("path");
const { execSync } = require("child_process");

const rootDir = path.resolve(__dirname, "..");
const baseManifestPath = path.join(rootDir, "manifests", "manifest.base.mv3.json");
const devManifestPath = path.join(rootDir, "basic-auth-extension", "manifest.json");

function readGitMessage() {
  return execSync("git log -1 --pretty=%B", { encoding: "utf8" }).trim();
}

function getBumpLevel(message) {
  const header = message.split("\n")[0] || "";
  if (/^chore: bump version/i.test(header)) {
    return null;
  }
  if (/BREAKING CHANGE/i.test(message) || /^[a-zA-Z]+(\(.+\))?!:/.test(header)) {
    return "major";
  }
  if (/^feat(\(.+\))?:/i.test(header)) {
    return "minor";
  }
  if (/^fix(\(.+\))?:/i.test(header)) {
    return "patch";
  }
  return null;
}

function bumpVersion(version, level) {
  const parts = version.split(".").map((value) => Number.parseInt(value, 10));
  if (parts.length !== 3 || parts.some((value) => Number.isNaN(value))) {
    throw new Error(`Invalid version: ${version}`);
  }
  const [major, minor, patch] = parts;
  if (level === "major") {
    return `${major + 1}.0.0`;
  }
  if (level === "minor") {
    return `${major}.${minor + 1}.0`;
  }
  return `${major}.${minor}.${patch + 1}`;
}

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

async function writeJson(filePath, data) {
  await fs.writeFile(filePath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
}

async function updateVersion(filePath, nextVersion) {
  const manifest = await readJson(filePath);
  manifest.version = nextVersion;
  await writeJson(filePath, manifest);
}

async function main() {
  const message = readGitMessage();
  const level = getBumpLevel(message);
  if (!level) {
    console.log("No semantic version bump required.");
    return;
  }

  const baseManifest = await readJson(baseManifestPath);
  const currentVersion = baseManifest.version;
  const nextVersion = bumpVersion(currentVersion, level);

  await updateVersion(baseManifestPath, nextVersion);
  await updateVersion(devManifestPath, nextVersion);

  console.log(`Version bumped to ${nextVersion}.`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
