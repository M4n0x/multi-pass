# Multi-pass V2

Multi-pass V2 is a browser extension that supplies HTTP Basic Auth credentials based on regex rules. It supports local rules, synced rules from shared JSON snippets, conflict detection, and per-tab status indicators.

![Popup UI](docs/images/popup.png)

![Options UI](docs/images/page.png)

## Features
- Regex-based Basic Auth rules with priority ordering.
- Per-tab status with conflict warnings.
- **Security vault lock (MV3):** optional master password, encrypted credentials at rest, lock/unlock from popup.
- **Biometric unlock (MV3):** optional Touch ID / Windows Hello-style unlock via WebAuthn with password fallback.
- Sync rules from HTTPS JSON snippets (GitLab snippet links supported).
- Import/export for local rules only.
- Chromium MV3 and Firefox MV3 builds.

## Usage
1. Load the extension in your browser.
2. (Optional, recommended) In Settings → Security, enable the vault with a master password.
3. (Optional) In Settings → Security, enable biometric unlock.
4. Open a Basic Auth page and click **Add rule** to create a new entry.
5. Edit the rule details and **Save**.
6. Use the options page to import/export or add sync sources.

When vault lock is enabled, credentials are only usable after unlocking the extension in the popup.
If biometric unlock is enabled, you can unlock with biometrics (when available) or fallback to password.
Changing or disabling the vault password resets biometric unlock and requires setup again.

> Note: biometric unlock is available on all current builds (MV3).

## Build
Generate bundles for Chromium and Firefox:

```bash
node scripts/build.js
```

Artifacts are written to `dist/` and zipped per target.

## Automated screenshots (README + store assets)
Generate fresh screenshots for README and store submissions:

```bash
npm install
npx playwright install chromium
npm run screenshots
```

Outputs:
- README images: `docs/images/page.png`, `docs/images/popup.png`
- Raw captures: `docs/store-assets/raw/`
- Chrome Web Store assets: `docs/store-assets/chrome/`
- Firefox Developer Hub assets: `docs/store-assets/firefox/`

Optional flags:
- `--headless` (for CI/Xvfb environments)
- `--skip-build` (if `dist/chromium` is already prepared)
- `--extension-dir <path>` (use a custom unpacked extension build)

## Versioning
Semantic commits are used to automatically bump the version on `main` and publish a GitHub release.
