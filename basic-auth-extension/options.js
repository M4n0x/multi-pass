import {
  generateId,
  getRules,
  getSyncSources,
  isValidRegex,
  saveRules,
  saveSyncSources
} from "./shared/storage.js";

const exportButton = document.getElementById("export-btn");
const exportResult = document.getElementById("export-result");
const importButton = document.getElementById("import-btn");
const importFile = document.getElementById("import-file");
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
    resyncButton.addEventListener("click", () => resyncSource(source.id));
    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.textContent = "Remove";
    removeButton.addEventListener("click", () => removeSyncSource(source.id));
    actions.append(resyncButton, removeButton);

    item.append(title, url, meta, actions);
    syncList.append(item);
  }
}

async function refreshView() {
  const [rules, syncSources] = await Promise.all([getRules(), getSyncSources()]);
  summary.textContent = `Rules: ${rules.length}`;
  renderRulesList(rules);
  renderSyncSources(syncSources, rules);
}

async function handleExport() {
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
}

async function handleImport() {
  const file = importFile.files?.[0];
  if (!file) {
    showImportResult("Select a JSON file to import.", true);
    return;
  }
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    const incoming = parseIncomingRules(parsed);

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
  } catch (error) {
    showImportResult("Import failed. Ensure the file is valid JSON.", true);
  } finally {
    importFile.value = "";
  }
}

async function fetchRulesFromUrl(url) {
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
    showSyncResult("Sync failed. Check the URL and JSON format.", true);
  }
}

async function resyncSource(sourceId) {
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
    showSyncResult("Re-sync failed. Check the URL and JSON format.", true);
  }
}

async function removeSyncSource(sourceId) {
  const [sources, rules] = await Promise.all([getSyncSources(), getRules()]);
  const nextSources = sources.filter((source) => source.id !== sourceId);
  const nextRules = rules.filter((rule) => rule.syncSourceId !== sourceId);
  await saveSyncSources(nextSources);
  await saveRules(nextRules);
  await refreshView();
  showSyncResult("Sync source removed.");
}

exportButton.addEventListener("click", handleExport);
importButton.addEventListener("click", handleImport);
syncAddButton.addEventListener("click", addSyncSource);

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local" || (!changes.rules && !changes.syncSources)) {
    return;
  }
  refreshView();
});

refreshView();
