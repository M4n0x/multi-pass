import {
  changeVaultPassword,
  disableVault,
  enableVault,
  generateId,
  getRules,
  getSyncSources,
  getVaultState,
  isValidRegex,
  isVaultLockedError,
  lockVault,
  saveRules,
  saveSyncSources,
  unlockVault
} from "./shared/storage.js";

const exportButton = document.getElementById("export-btn");
const exportResult = document.getElementById("export-result");
const importButton = document.getElementById("import-btn");
const importFile = document.getElementById("import-file");
const importText = document.getElementById("import-text");
const importPasteButton = document.getElementById("import-paste-btn");
const importResult = document.getElementById("import-result");
const summary = document.getElementById("summary");
const rulesList = document.getElementById("rules-list");
const rulesEmpty = document.getElementById("rules-empty");
const syncLabelInput = document.getElementById("sync-label");
const syncUrlInput = document.getElementById("sync-url");
const syncAddButton = document.getElementById("sync-add");
const syncResult = document.getElementById("sync-result");
const syncList = document.getElementById("sync-list");
const syncEmpty = document.getElementById("sync-empty");
const syncWhyButton = document.getElementById("sync-warning-why");
const syncPopover = document.getElementById("sync-warning-popover");
const vaultNotice = document.getElementById("vault-notice");

const tabImportButton = document.getElementById("tab-import-btn");
const tabSecurityButton = document.getElementById("tab-security-btn");
const tabImportPanel = document.getElementById("tab-import");
const tabSecurityPanel = document.getElementById("tab-security");

const securitySetup = document.getElementById("security-setup");
const securityLocked = document.getElementById("security-locked");
const securityOpen = document.getElementById("security-open");
const securityResult = document.getElementById("security-result");

const securitySetupPassword = document.getElementById("security-setup-password");
const securitySetupConfirm = document.getElementById("security-setup-confirm");
const securityEnableButton = document.getElementById("security-enable-btn");

const securityUnlockPassword = document.getElementById("security-unlock-password");
const securityUnlockButton = document.getElementById("security-unlock-btn");

const securityLockButton = document.getElementById("security-lock-btn");
const securityDisableButton = document.getElementById("security-disable-btn");

const securityCurrentPassword = document.getElementById("security-current-password");
const securityNextPassword = document.getElementById("security-next-password");
const securityNextConfirm = document.getElementById("security-next-confirm");
const securityChangeButton = document.getElementById("security-change-btn");

let optionsLocked = false;

function showImportResult(message, isError = false) {
  importResult.hidden = false;
  importResult.textContent = message;
  importResult.style.borderColor = isError ? "#fca5a5" : "#cbd2d9";
  importResult.style.background = isError ? "#fff5f5" : "#f8fafc";
  importResult.style.color = isError ? "#b91c1c" : "#1f2933";
}

function showExportResult(message, isError = false) {
  exportResult.hidden = false;
  exportResult.textContent = message;
  exportResult.style.borderColor = isError ? "#fca5a5" : "#cbd2d9";
  exportResult.style.background = isError ? "#fff5f5" : "#f8fafc";
  exportResult.style.color = isError ? "#b91c1c" : "#1f2933";
}

function showSyncResult(message, isError = false) {
  syncResult.hidden = false;
  syncResult.textContent = message;
  syncResult.style.borderColor = isError ? "#fca5a5" : "#cbd2d9";
  syncResult.style.background = isError ? "#fff5f5" : "#f8fafc";
  syncResult.style.color = isError ? "#b91c1c" : "#1f2933";
}

function showSecurityResult(message, isError = false) {
  if (!securityResult) {
    return;
  }
  securityResult.hidden = false;
  securityResult.textContent = message;
  securityResult.style.borderColor = isError ? "#fca5a5" : "#cbd2d9";
  securityResult.style.background = isError ? "#fff5f5" : "#f8fafc";
  securityResult.style.color = isError ? "#b91c1c" : "#1f2933";
}

function clearSecurityResult() {
  if (!securityResult) {
    return;
  }
  securityResult.hidden = true;
  securityResult.textContent = "";
}

function mapVaultError(code) {
  switch (code) {
    case "weak-password":
      return "Use a stronger password (minimum 8 characters).";
    case "already-enabled":
      return "Vault lock is already enabled.";
    case "invalid-password":
      return "Invalid password.";
    case "locked":
      return "Unlock the vault first.";
    case "not-enabled":
      return "Vault lock is not enabled.";
    default:
      return "Security action failed.";
  }
}

function setActiveTab(tab) {
  const importActive = tab !== "security";
  tabImportButton?.classList.toggle("active", importActive);
  tabSecurityButton?.classList.toggle("active", !importActive);
  if (tabImportPanel) {
    tabImportPanel.hidden = !importActive;
  }
  if (tabSecurityPanel) {
    tabSecurityPanel.hidden = importActive;
  }
}

function closeSyncPopover() {
  if (!syncPopover || !syncWhyButton) {
    return;
  }
  if (syncPopover.hidden) {
    return;
  }
  syncPopover.hidden = true;
  syncWhyButton.setAttribute("aria-expanded", "false");
}

if (syncWhyButton && syncPopover) {
  syncWhyButton.addEventListener("click", (event) => {
    event.stopPropagation();
    if (syncPopover.hidden) {
      syncPopover.hidden = false;
      syncWhyButton.setAttribute("aria-expanded", "true");
      return;
    }
    closeSyncPopover();
  });

  document.addEventListener("click", (event) => {
    if (syncPopover.hidden) {
      return;
    }
    if (syncPopover.contains(event.target) || event.target === syncWhyButton) {
      return;
    }
    closeSyncPopover();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeSyncPopover();
    }
  });
}

function setControlsDisabled(disabled) {
  const controls = [
    exportButton,
    importButton,
    importPasteButton,
    syncAddButton,
    importFile,
    importText,
    syncLabelInput,
    syncUrlInput
  ];
  for (const control of controls) {
    if (!control) {
      continue;
    }
    control.disabled = disabled;
  }
}

function setLockedMode(locked) {
  optionsLocked = locked;
  setControlsDisabled(locked);
  if (vaultNotice) {
    vaultNotice.hidden = !locked;
  }
  if (locked) {
    summary.textContent = "Rules: locked";
    renderRulesList([]);
  }
}

async function refreshLockState() {
  const vault = await getVaultState();
  const locked = Boolean(vault.supported && vault.enabled && !vault.unlocked);
  setLockedMode(locked);
  return locked;
}

async function refreshSecurityState() {
  const vault = await getVaultState();

  if (securitySetup) {
    securitySetup.hidden = true;
  }
  if (securityLocked) {
    securityLocked.hidden = true;
  }
  if (securityOpen) {
    securityOpen.hidden = true;
  }

  if (!vault.supported) {
    showSecurityResult("Vault controls are not available in this browser build.", true);
    return vault;
  }

  clearSecurityResult();

  if (!vault.enabled) {
    if (securitySetup) {
      securitySetup.hidden = false;
    }
    return vault;
  }

  if (!vault.unlocked) {
    if (securityLocked) {
      securityLocked.hidden = false;
    }
    return vault;
  }

  if (securityOpen) {
    securityOpen.hidden = false;
  }
  return vault;
}

function isLockedError(error) {
  return isVaultLockedError(error);
}

function isValidHttpsUrl(urlString) {
  try {
    const url = new URL(urlString);
    return url.protocol === "https:";
  } catch (error) {
    return false;
  }
}

function parseIncomingRules(parsed) {
  const incoming = Array.isArray(parsed) ? parsed : parsed?.rules;
  if (!Array.isArray(incoming)) {
    throw new Error("Invalid JSON format");
  }
  return incoming;
}

function uniqueUrls(urls) {
  return Array.from(new Set(urls.filter(Boolean)));
}

function buildSnippetCandidates(urlString) {
  let url;
  try {
    url = new URL(urlString);
  } catch (error) {
    return [];
  }
  if (url.protocol !== "https:") {
    return [];
  }
  const path = url.pathname;
  if (!path.includes("/snippets/")) {
    return [];
  }

  const candidates = [];
  const basePath = path.endsWith(".git") ? path.slice(0, -4) : path;
  const snippetId = basePath.split("/snippets/")[1]?.split("/")[0];

  const rawVariants = [
    `${basePath}/raw`,
    `${basePath}/raw?inline=false`,
    `${basePath}/raw?ref=main`,
    `${basePath}/raw?ref=master`
  ];
  candidates.push(...rawVariants.map((variant) => `${url.origin}${variant}`));

  if (!basePath.includes("/-/")) {
    const splitIndex = basePath.indexOf("/snippets/");
    if (splitIndex > -1) {
      const prefix = basePath.slice(0, splitIndex);
      const suffix = basePath.slice(splitIndex + 1);
      const dashPath = `${prefix}/-/${suffix}`;
      const dashVariants = [
        `${dashPath}/raw`,
        `${dashPath}/raw?inline=false`,
        `${dashPath}/raw?ref=main`,
        `${dashPath}/raw?ref=master`
      ];
      candidates.push(...dashVariants.map((variant) => `${url.origin}${variant}`));
    }
  }

  if (snippetId) {
    const projectPath = basePath.split("/snippets/")[0].replace(/^\//, "");
    if (projectPath) {
      const encodedProject = encodeURIComponent(projectPath);
      candidates.push(
        `${url.origin}/api/v4/projects/${encodedProject}/snippets/${snippetId}/raw`
      );
      candidates.push(
        `${url.origin}/api/v4/projects/${encodedProject}/snippets/${snippetId}/raw?ref=main`
      );
      candidates.push(
        `${url.origin}/api/v4/projects/${encodedProject}/snippets/${snippetId}/raw?ref=master`
      );
    }
    candidates.push(`${url.origin}/api/v4/snippets/${snippetId}/raw`);
  }

  return uniqueUrls(candidates);
}

function sanitizeRule(raw) {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const pattern = typeof raw.pattern === "string" ? raw.pattern.trim() : "";
  if (!isValidRegex(pattern)) {
    return null;
  }
  const nameSource =
    typeof raw.name === "string" && raw.name.trim()
      ? raw.name
      : typeof raw.label === "string" && raw.label.trim()
        ? raw.label
        : "Imported";
  const name = nameSource.trim();
  const username = typeof raw.username === "string" ? raw.username : "";
  const password = typeof raw.password === "string" ? raw.password : "";
  const enabled = typeof raw.enabled === "boolean" ? raw.enabled : true;
  const createdAt = Number.isFinite(raw.createdAt) ? raw.createdAt : Date.now();
  const id = typeof raw.id === "string" && raw.id.trim() ? raw.id.trim() : generateId();
  return {
    id,
    name,
    pattern,
    username,
    password,
    enabled,
    createdAt
  };
}

function extractHost(pattern) {
  if (!pattern || typeof pattern !== "string") {
    return "";
  }
  const match = pattern.match(/https\?:\/\/([^/]+)/i);
  if (!match) {
    return "";
  }
  return match[1].replace(/\\\./g, ".");
}

function getRuleTitle(rule) {
  if (rule.name && rule.name.trim()) {
    return rule.name.trim();
  }
  const host = extractHost(rule.pattern);
  return host || "Untitled rule";
}

function getSourceLabel(source) {
  if (source.name && source.name.trim()) {
    return source.name.trim();
  }
  try {
    return new URL(source.url).host;
  } catch (error) {
    return "Sync source";
  }
}

function formatTimestamp(timestamp) {
  if (!timestamp) {
    return "Never";
  }
  return new Date(timestamp).toLocaleString();
}

function buildRuleSignature(rule) {
  return `${rule.pattern}::${rule.username}`;
}

function buildSyncedRules(incoming, syncSourceId, existingRules) {
  const enabledMap = new Map(
    existingRules.map((rule) => [buildRuleSignature(rule), rule.enabled !== false])
  );
  const synced = [];
  for (const entry of incoming) {
    const rule = sanitizeRule(entry);
    if (!rule) {
      continue;
    }
    const signature = buildRuleSignature(rule);
    const enabled = enabledMap.has(signature) ? enabledMap.get(signature) : rule.enabled;
    synced.push({
      ...rule,
      id: generateId(),
      enabled,
      syncSourceId
    });
  }
  return synced;
}

function mergeSyncedRules(allRules, syncSourceId, syncedRules) {
  const firstIndex = allRules.findIndex((rule) => rule.syncSourceId === syncSourceId);
  const remaining = allRules.filter((rule) => rule.syncSourceId !== syncSourceId);
  const insertIndex = firstIndex === -1 ? remaining.length : Math.min(firstIndex, remaining.length);
  return [
    ...remaining.slice(0, insertIndex),
    ...syncedRules,
    ...remaining.slice(insertIndex)
  ];
}

function renderRulesList(rules) {
  rulesList.innerHTML = "";
  if (!rules.length) {
    rulesEmpty.hidden = false;
    return;
  }
  rulesEmpty.hidden = true;

  for (const rule of rules) {
    const item = document.createElement("div");
    item.className = "rule-item";
    if (rule.enabled === false) {
      item.classList.add("disabled");
    }

    const title = document.createElement("div");
    title.className = "rule-title";
    title.textContent = getRuleTitle(rule);
    if (rule.syncSourceId) {
      const badge = document.createElement("span");
      badge.className = "sync-badge";
      badge.textContent = "Sync";
      title.append(badge);
    }

    const meta = document.createElement("div");
    meta.className = "rule-meta";
    const user = document.createElement("span");
    user.textContent = rule.username ? `User: ${rule.username}` : "No username";
    const enabled = document.createElement("span");
    enabled.textContent = rule.enabled === false ? "Disabled" : "Enabled";
    meta.append(user, enabled);

    const pattern = document.createElement("div");
    pattern.className = "rule-pattern";
    pattern.textContent = rule.pattern || "(no pattern)";

    item.append(title, meta, pattern);
    rulesList.append(item);
  }
}

function renderSyncSources(sources, rules) {
  syncList.innerHTML = "";
  if (!sources.length) {
    syncEmpty.hidden = false;
    return;
  }
  syncEmpty.hidden = true;

  for (const source of sources) {
    const item = document.createElement("div");
    item.className = "sync-item";

    const title = document.createElement("div");
    title.className = "sync-title";
    title.textContent = getSourceLabel(source);

    const url = document.createElement("div");
    url.className = "sync-url";
    url.textContent = source.url;

    const meta = document.createElement("div");
    meta.className = "sync-meta";
    const syncedAt = document.createElement("span");
    syncedAt.textContent = `Last synced: ${formatTimestamp(source.lastSynced)}`;
    const count = document.createElement("span");
    const ruleCount = rules.filter((rule) => rule.syncSourceId === source.id).length;
    count.textContent = `Rules: ${ruleCount}`;
    meta.append(syncedAt, count);

    const actions = document.createElement("div");
    actions.className = "sync-actions";
    const resyncButton = document.createElement("button");
    resyncButton.type = "button";
    resyncButton.textContent = "Re-sync";
    resyncButton.disabled = optionsLocked;
    resyncButton.addEventListener("click", () => resyncSource(source.id));
    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.textContent = "Remove";
    removeButton.disabled = optionsLocked;
    removeButton.addEventListener("click", () => removeSyncSource(source.id));
    actions.append(resyncButton, removeButton);

    item.append(title, url, meta, actions);
    syncList.append(item);
  }
}

async function refreshView() {
  const locked = await refreshLockState();
  const syncSources = await getSyncSources();

  if (locked) {
    renderSyncSources(syncSources, []);
    return;
  }

  try {
    const rules = await getRules();
    summary.textContent = `Rules: ${rules.length}`;
    renderRulesList(rules);
    renderSyncSources(syncSources, rules);
  } catch (error) {
    if (isLockedError(error)) {
      setLockedMode(true);
      renderSyncSources(syncSources, []);
      return;
    }
    throw error;
  }
}

async function handleExport() {
  if (optionsLocked) {
    showExportResult("Vault is locked. Unlock from the popup first.", true);
    return;
  }
  try {
    const rules = (await getRules()).filter((rule) => !rule.syncSourceId);
    const payload = JSON.stringify({ rules }, null, 2);
    const blob = new Blob([payload], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "basic-auth-rules.json";
    link.click();
    URL.revokeObjectURL(url);
    showExportResult("Exported rules successfully.");
  } catch (error) {
    if (isLockedError(error)) {
      await refreshView();
      showExportResult("Vault is locked. Unlock from the popup first.", true);
      return;
    }
    showExportResult("Export failed.", true);
  }
}

async function applyIncomingRules(incoming) {
  const existing = await getRules();
  const existingById = new Map(existing.map((rule, index) => [rule.id, index]));
  let added = 0;
  let updated = 0;
  let skipped = 0;
  const newRules = [];
  const merged = [...existing];

  for (const entry of incoming) {
    const rule = sanitizeRule(entry);
    if (!rule) {
      skipped += 1;
      continue;
    }
    if (existingById.has(rule.id)) {
      const index = existingById.get(rule.id);
      merged[index] = rule;
      updated += 1;
    } else {
      newRules.push(rule);
      added += 1;
    }
  }

  const nextRules = [...newRules, ...merged];
  await saveRules(nextRules);
  await refreshView();
  showImportResult(`Import complete: ${added} added, ${updated} updated, ${skipped} skipped.`);
}

async function handleFileImport() {
  if (optionsLocked) {
    showImportResult("Vault is locked. Unlock from the popup first.", true);
    return;
  }
  const file = importFile.files?.[0];
  if (!file) {
    showImportResult("Select a JSON or text file to import.", true);
    return;
  }
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    const incoming = parseIncomingRules(parsed);
    await applyIncomingRules(incoming);
  } catch (error) {
    if (isLockedError(error)) {
      await refreshView();
      showImportResult("Vault is locked. Unlock from the popup first.", true);
      return;
    }
    showImportResult("Import failed. Ensure the file is valid JSON.", true);
  } finally {
    importFile.value = "";
  }
}

async function handlePasteImport() {
  if (optionsLocked) {
    showImportResult("Vault is locked. Unlock from the popup first.", true);
    return;
  }
  const text = importText.value.trim();
  if (!text) {
    showImportResult("Paste JSON to import.", true);
    return;
  }
  try {
    const parsed = JSON.parse(text);
    const incoming = parseIncomingRules(parsed);
    await applyIncomingRules(incoming);
    importText.value = "";
  } catch (error) {
    if (isLockedError(error)) {
      await refreshView();
      showImportResult("Vault is locked. Unlock from the popup first.", true);
      return;
    }
    showImportResult("Import failed. Ensure the pasted JSON is valid.", true);
  }
}

async function fetchRulesFromUrl(url) {
  if (!isValidHttpsUrl(url)) {
    throw new Error("Only HTTPS URLs are allowed.");
  }

  const candidates = uniqueUrls([url, ...buildSnippetCandidates(url)]);
  let lastError = null;

  for (const candidate of candidates) {
    try {
      const response = await fetch(candidate, { cache: "no-store" });
      if (!response.ok) {
        lastError = new Error("Failed to fetch rules");
        continue;
      }
      const text = await response.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch (error) {
        lastError = error;
        continue;
      }
      return parseIncomingRules(parsed);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error("Failed to fetch rules");
}

async function addSyncSource() {
  if (optionsLocked) {
    showSyncResult("Vault is locked. Unlock from the popup first.", true);
    return;
  }
  const url = syncUrlInput.value.trim();
  const label = syncLabelInput.value.trim();
  if (!isValidHttpsUrl(url)) {
    showSyncResult("Enter a valid HTTPS URL.", true);
    return;
  }
  try {
    const sources = await getSyncSources();
    if (sources.some((source) => source.url === url)) {
      showSyncResult("This URL is already synced.", true);
      return;
    }
    const incoming = await fetchRulesFromUrl(url);
    const existingRules = await getRules();
    const newSource = {
      id: generateId(),
      url,
      name: label || new URL(url).host,
      lastSynced: Date.now()
    };
    const syncedRules = buildSyncedRules(incoming, newSource.id, []);
    const nextRules = [...existingRules, ...syncedRules];
    await saveSyncSources([...sources, newSource]);
    await saveRules(nextRules);
    await refreshView();
    syncUrlInput.value = "";
    syncLabelInput.value = "";
    showSyncResult(`Synced ${syncedRules.length} rules from ${newSource.name}.`);
  } catch (error) {
    if (isLockedError(error)) {
      await refreshView();
      showSyncResult("Vault is locked. Unlock from the popup first.", true);
      return;
    }
    showSyncResult(error?.message || "Sync failed. Check the URL and JSON format.", true);
  }
}

async function resyncSource(sourceId) {
  if (optionsLocked) {
    showSyncResult("Vault is locked. Unlock from the popup first.", true);
    return;
  }
  try {
    const [sources, existingRules] = await Promise.all([getSyncSources(), getRules()]);
    const source = sources.find((item) => item.id === sourceId);
    if (!source) {
      return;
    }
    const incoming = await fetchRulesFromUrl(source.url);
    const existingForSource = existingRules.filter((rule) => rule.syncSourceId === sourceId);
    const syncedRules = buildSyncedRules(incoming, sourceId, existingForSource);
    const nextRules = mergeSyncedRules(existingRules, sourceId, syncedRules);
    const nextSources = sources.map((item) =>
      item.id === sourceId ? { ...item, lastSynced: Date.now() } : item
    );
    await saveSyncSources(nextSources);
    await saveRules(nextRules);
    await refreshView();
    showSyncResult(`Re-synced ${syncedRules.length} rules from ${getSourceLabel(source)}.`);
  } catch (error) {
    if (isLockedError(error)) {
      await refreshView();
      showSyncResult("Vault is locked. Unlock from the popup first.", true);
      return;
    }
    showSyncResult(error?.message || "Re-sync failed. Check the URL and JSON format.", true);
  }
}

async function removeSyncSource(sourceId) {
  if (optionsLocked) {
    showSyncResult("Vault is locked. Unlock from the popup first.", true);
    return;
  }
  try {
    const [sources, rules] = await Promise.all([getSyncSources(), getRules()]);
    const nextSources = sources.filter((source) => source.id !== sourceId);
    const nextRules = rules.filter((rule) => rule.syncSourceId !== sourceId);
    await saveSyncSources(nextSources);
    await saveRules(nextRules);
    await refreshView();
    showSyncResult("Sync source removed.");
  } catch (error) {
    if (isLockedError(error)) {
      await refreshView();
      showSyncResult("Vault is locked. Unlock from the popup first.", true);
      return;
    }
    showSyncResult("Failed to remove sync source.", true);
  }
}

async function handleSecurityEnable() {
  clearSecurityResult();
  const password = securitySetupPassword?.value || "";
  const confirm = securitySetupConfirm?.value || "";

  if (password.length < 8) {
    showSecurityResult("Password must be at least 8 characters.", true);
    return;
  }
  if (password !== confirm) {
    showSecurityResult("Passwords do not match.", true);
    return;
  }

  const result = await enableVault(password);
  if (!result.ok) {
    showSecurityResult(mapVaultError(result.error), true);
    return;
  }

  if (securitySetupPassword) securitySetupPassword.value = "";
  if (securitySetupConfirm) securitySetupConfirm.value = "";
  showSecurityResult("Vault lock enabled.");
  await refreshSecurityState();
  await refreshView();
}

async function handleSecurityUnlock() {
  clearSecurityResult();
  const password = securityUnlockPassword?.value || "";
  const result = await unlockVault(password);
  if (!result.ok) {
    showSecurityResult(mapVaultError(result.error), true);
    return;
  }
  if (securityUnlockPassword) securityUnlockPassword.value = "";
  showSecurityResult("Vault unlocked.");
  await refreshSecurityState();
  await refreshView();
}

async function handleSecurityLock() {
  clearSecurityResult();
  const result = await lockVault();
  if (!result.ok) {
    showSecurityResult(mapVaultError(result.error), true);
    return;
  }
  showSecurityResult("Vault locked.");
  await refreshSecurityState();
  await refreshView();
}

async function handleSecurityDisable() {
  clearSecurityResult();
  if (!window.confirm("Disable vault lock and store rules unencrypted?")) {
    return;
  }
  const result = await disableVault();
  if (!result.ok) {
    showSecurityResult(mapVaultError(result.error), true);
    return;
  }
  showSecurityResult("Vault lock disabled.");
  await refreshSecurityState();
  await refreshView();
}

async function handleSecurityChangePassword() {
  clearSecurityResult();
  const currentPassword = securityCurrentPassword?.value || "";
  const nextPassword = securityNextPassword?.value || "";
  const nextConfirm = securityNextConfirm?.value || "";

  if (nextPassword.length < 8) {
    showSecurityResult("New password must be at least 8 characters.", true);
    return;
  }
  if (nextPassword !== nextConfirm) {
    showSecurityResult("New passwords do not match.", true);
    return;
  }

  const result = await changeVaultPassword(currentPassword, nextPassword);
  if (!result.ok) {
    showSecurityResult(mapVaultError(result.error), true);
    return;
  }

  if (securityCurrentPassword) securityCurrentPassword.value = "";
  if (securityNextPassword) securityNextPassword.value = "";
  if (securityNextConfirm) securityNextConfirm.value = "";
  showSecurityResult("Password updated.");
}

exportButton.addEventListener("click", handleExport);
importButton.addEventListener("click", handleFileImport);
importPasteButton.addEventListener("click", handlePasteImport);
syncAddButton.addEventListener("click", addSyncSource);

tabImportButton?.addEventListener("click", () => setActiveTab("import"));
tabSecurityButton?.addEventListener("click", async () => {
  setActiveTab("security");
  await refreshSecurityState();
});

securityEnableButton?.addEventListener("click", handleSecurityEnable);
securityUnlockButton?.addEventListener("click", handleSecurityUnlock);
securityLockButton?.addEventListener("click", handleSecurityLock);
securityDisableButton?.addEventListener("click", handleSecurityDisable);
securityChangeButton?.addEventListener("click", handleSecurityChangePassword);

securityUnlockPassword?.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    handleSecurityUnlock();
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local" || (!changes.rules && !changes.syncSources && !changes.vaultPayload)) {
    return;
  }
  refreshSecurityState();
  refreshView();
});

setActiveTab("import");
refreshSecurityState();
refreshView();
