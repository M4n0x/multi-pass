#!/usr/bin/env node
const fs = require("fs/promises");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

function tryRequire(moduleName) {
  try {
    // eslint-disable-next-line import/no-dynamic-require, global-require
    return require(moduleName);
  } catch (error) {
    return null;
  }
}

const playwright = tryRequire("playwright");
const sharp = tryRequire("sharp");

if (!playwright || !sharp) {
  console.error("Missing dependencies for screenshot automation.");
  console.error("Run: npm install");
  console.error("Then ensure Chromium is available for Playwright:");
  console.error("  npx playwright install chromium");
  process.exit(1);
}

const { chromium } = playwright;

const ROOT_DIR = path.resolve(__dirname, "..");
const DIST_DIR = path.join(ROOT_DIR, "dist");
const DEFAULT_EXTENSION_DIR = path.join(DIST_DIR, "chromium");

const RAW_DIR = path.join(ROOT_DIR, "docs", "store-assets", "raw");
const CHROME_DIR = path.join(ROOT_DIR, "docs", "store-assets", "chrome");
const FIREFOX_DIR = path.join(ROOT_DIR, "docs", "store-assets", "firefox");
const README_IMG_DIR = path.join(ROOT_DIR, "docs", "images");

function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = {
    extensionDir: DEFAULT_EXTENSION_DIR,
    headless: false,
    skipBuild: false
  };

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    if (token === "--headless") {
      parsed.headless = true;
      continue;
    }
    if (token === "--skip-build") {
      parsed.skipBuild = true;
      continue;
    }
    if (token === "--extension-dir" && args[i + 1]) {
      parsed.extensionDir = path.resolve(args[i + 1]);
      i += 1;
      continue;
    }
  }

  return parsed;
}

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch (error) {
    return false;
  }
}

async function ensureExtensionBuild(extensionDir, skipBuild) {
  const manifestPath = path.join(extensionDir, "manifest.json");
  if (skipBuild && (await exists(manifestPath))) {
    return;
  }

  if (!(await exists(manifestPath))) {
    console.log("No extension build found. Running node scripts/build.js...");
    execSync("node scripts/build.js", { cwd: ROOT_DIR, stdio: "inherit" });
  }

  if (!(await exists(manifestPath))) {
    throw new Error(`Extension manifest not found at ${manifestPath}`);
  }
}

async function ensureDirs() {
  await fs.mkdir(RAW_DIR, { recursive: true });
  await fs.mkdir(CHROME_DIR, { recursive: true });
  await fs.mkdir(FIREFOX_DIR, { recursive: true });
  await fs.mkdir(README_IMG_DIR, { recursive: true });
}

async function sendRuntimeMessage(page, message) {
  return page.evaluate(
    (payload) =>
      new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(payload, (response) => {
          const err = chrome.runtime.lastError;
          if (err) {
            reject(new Error(err.message));
            return;
          }
          resolve(response || null);
        });
      }),
    message
  );
}

async function setLocal(page, payload) {
  return page.evaluate(
    (values) =>
      new Promise((resolve, reject) => {
        chrome.storage.local.set(values, () => {
          const err = chrome.runtime.lastError;
          if (err) {
            reject(new Error(err.message));
            return;
          }
          resolve();
        });
      }),
    payload
  );
}

async function removeLocal(page, keys) {
  return page.evaluate(
    (value) =>
      new Promise((resolve, reject) => {
        chrome.storage.local.remove(value, () => {
          const err = chrome.runtime.lastError;
          if (err) {
            reject(new Error(err.message));
            return;
          }
          resolve();
        });
      }),
    keys
  );
}

function demoRules() {
  return [
    {
      id: "rule-demo-api",
      name: "Staging API",
      pattern: "^https?://staging\\.example\\.com/.*",
      username: "demo.user",
      password: "S3cur3-P4ss",
      enabled: true,
      createdAt: Date.now() - 10_000
    },
    {
      id: "rule-demo-admin",
      name: "Admin Portal",
      pattern: "^https?://admin\\.example\\.com/.*",
      username: "admin@example.com",
      password: "Sup3r-Admin",
      enabled: true,
      createdAt: Date.now() - 8_000
    },
    {
      id: "rule-demo-backup",
      name: "Legacy",
      pattern: "^https?://legacy\\.example\\.com/.*",
      username: "legacy.user",
      password: "Legacy-P4ss",
      enabled: false,
      createdAt: Date.now() - 6_000
    }
  ];
}

function demoSyncSources() {
  return [
    {
      id: "sync-demo-source",
      url: "https://gitlab.example.com/snippets/1234/raw",
      name: "Team shared credentials",
      lastSynced: Date.now() - 60_000
    }
  ];
}

async function seedDemoData(page) {
  await setLocal(page, {
    rules: demoRules(),
    syncSources: demoSyncSources(),
    vaultSettings: { lockOnBrowserClose: true }
  });

  await removeLocal(page, ["vaultPayload", "vaultWebAuthnV1", "vaultPersistentSessionKeyV1"]);
}

async function prepareLockedVault(page) {
  const password = "DemoVault!123";
  const enabled = await sendRuntimeMessage(page, { type: "enableVault", password });
  if (!enabled?.ok && enabled?.error !== "already-enabled") {
    throw new Error(`Unable to enable vault for screenshot: ${JSON.stringify(enabled)}`);
  }

  const locked = await sendRuntimeMessage(page, { type: "lockVault" });
  if (!locked?.ok) {
    throw new Error(`Unable to lock vault for screenshot: ${JSON.stringify(locked)}`);
  }
}

async function screenshotPopup(context, popupUrl, outPath) {
  const popup = await context.newPage();
  await popup.setViewportSize({ width: 1200, height: 900 });
  await popup.goto(popupUrl, { waitUntil: "domcontentloaded" });
  await popup.waitForTimeout(300);

  const app = popup.locator(".app");
  const box = await app.boundingBox();

  if (!box) {
    throw new Error("Unable to locate popup root for screenshot");
  }

  const clip = {
    x: Math.max(0, box.x - 24),
    y: Math.max(0, box.y - 24),
    width: Math.min(1200, box.width + 48),
    height: Math.min(900, box.height + 48)
  };

  await popup.screenshot({ path: outPath, clip });
  await popup.close();
}

async function screenshotOptions(page, outPath) {
  await page.waitForTimeout(250);
  await page.screenshot({ path: outPath, fullPage: true });
}

async function renderContain(inputPath, outputPath, width, height, background = "#eef2f7") {
  await sharp(inputPath)
    .resize(width, height, {
      fit: "contain",
      background
    })
    .png({ compressionLevel: 9 })
    .toFile(outputPath);
}

async function renderCover(inputPath, outputPath, width, height) {
  await sharp(inputPath)
    .resize(width, height, {
      fit: "cover",
      position: "attention"
    })
    .png({ compressionLevel: 9 })
    .toFile(outputPath);
}

async function buildAssets(rawOptions, rawSecurity, rawPopup) {
  await Promise.all([
    // README images
    renderCover(rawOptions, path.join(README_IMG_DIR, "page.png"), 1600, 980),
    renderContain(rawPopup, path.join(README_IMG_DIR, "popup.png"), 1200, 800),

    // Chrome store assets
    renderCover(rawOptions, path.join(CHROME_DIR, "screenshot-1-overview.png"), 1280, 800),
    renderContain(rawPopup, path.join(CHROME_DIR, "screenshot-2-popup.png"), 1280, 800),
    renderCover(rawSecurity, path.join(CHROME_DIR, "screenshot-3-security.png"), 1280, 800),
    renderCover(rawOptions, path.join(CHROME_DIR, "small-promo-tile-440x280.png"), 440, 280),
    renderCover(rawSecurity, path.join(CHROME_DIR, "marquee-promo-tile-1400x560.png"), 1400, 560),

    // Firefox developer hub assets
    renderCover(rawOptions, path.join(FIREFOX_DIR, "screenshot-1-overview.png"), 1280, 800),
    renderContain(rawPopup, path.join(FIREFOX_DIR, "screenshot-2-popup.png"), 1280, 800),
    renderCover(rawSecurity, path.join(FIREFOX_DIR, "screenshot-3-security.png"), 1280, 800),
    renderCover(rawSecurity, path.join(FIREFOX_DIR, "promotional-1400x560.png"), 1400, 560)
  ]);
}

async function main() {
  const args = parseArgs();
  await ensureExtensionBuild(args.extensionDir, args.skipBuild);
  await ensureDirs();

  const userDataDir = await fs.mkdtemp(path.join(os.tmpdir(), "multi-pass-shot-"));
  let context;

  try {
    context = await chromium.launchPersistentContext(userDataDir, {
      headless: args.headless,
      viewport: { width: 1600, height: 1024 },
      deviceScaleFactor: 2,
      args: [
        `--disable-extensions-except=${args.extensionDir}`,
        `--load-extension=${args.extensionDir}`
      ]
    });

    const sw =
      context.serviceWorkers()[0] ||
      (await context.waitForEvent("serviceworker", { timeout: 15_000 }));
    const extensionId = new URL(sw.url()).host;

    const optionsUrl = `chrome-extension://${extensionId}/options.html`;
    const popupUrl = `chrome-extension://${extensionId}/popup.html`;

    const page = await context.newPage();
    await page.goto(optionsUrl, { waitUntil: "domcontentloaded" });

    await seedDemoData(page);
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForSelector("#summary");

    const rawOptions = path.join(RAW_DIR, "options-import.png");
    const rawSecurity = path.join(RAW_DIR, "options-security-locked.png");
    const rawPopup = path.join(RAW_DIR, "popup-locked.png");

    await screenshotOptions(page, rawOptions);

    await prepareLockedVault(page);
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.click("#tab-security-btn");
    await page.waitForTimeout(300);
    await screenshotOptions(page, rawSecurity);

    await screenshotPopup(context, popupUrl, rawPopup);

    await buildAssets(rawOptions, rawSecurity, rawPopup);

    console.log("Screenshots generated successfully.");
    console.log(`README images: ${README_IMG_DIR}`);
    console.log(`Chrome store assets: ${CHROME_DIR}`);
    console.log(`Firefox store assets: ${FIREFOX_DIR}`);
  } finally {
    if (context) {
      await context.close();
    }
    await fs.rm(userDataDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  const text = String(error?.message || error || "");
  if (text.includes("error while loading shared libraries")) {
    console.error("Playwright browser dependencies are missing on this machine.");
    console.error("Try:");
    console.error("  npx playwright install --with-deps chromium");
    console.error("or run on a workstation with Chrome/Chromium installed.");
  }
  console.error(error);
  process.exit(1);
});
