import { STATUS_LABELS } from "./shared/constants.js";
import { generateId, getRules, isValidRegex, saveRules } from "./shared/storage.js";

const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const versionLabel = document.getElementById("app-version");
const rulesList = document.getElementById("rules-list");
const emptyState = document.getElementById("empty-state");
const ruleCount = document.getElementById("rule-count");
const addRuleButton = document.getElementById("add-rule");
const openOptionsButton = document.getElementById("open-options");

const STATUS_CLASSES = {
  idle: "status-idle",
  ok: "status-ok",
  auth_failed: "status-failed",
  conflict: "status-conflict"
};

let currentTab = null;
let rules = [];
let pendingFocus = null;
let activeRuleId = null;
let currentStatus = "idle";
let conflictRuleIds = [];
const expandedRuleIds = new Set();
let sortableInstance = null;

function queryTabs(queryInfo) {
  return new Promise((resolve) => {
    chrome.tabs.query(queryInfo, (tabs) => resolve(tabs || []));
  });
}

function sendRuntimeMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        resolve(null);
        return;
      }
      resolve(response);
    });
  });
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildDefaultPattern(urlString) {
  try {
    const url = new URL(urlString);
    return `^https?://${escapeRegex(url.host)}/.*`;
  } catch (error) {
    return "";
  }
}

function updateStatus(state) {
  const safeState = state && STATUS_LABELS[state] ? state : "idle";
  statusText.textContent = STATUS_LABELS[safeState] || "Idle";
  statusDot.className = `status-dot ${STATUS_CLASSES[safeState] || "status-idle"}`;
}

async function refreshStatus() {
  if (!currentTab?.id) {
    updateStatus("idle");
    activeRuleId = null;
    currentStatus = "idle";
    conflictRuleIds = [];
    applyActiveRuleIndicators();
    return;
  }
  const response = await sendRuntimeMessage({
    type: "getTabStatus",
    tabId: currentTab.id
  });
  currentStatus = response?.status || "idle";
  updateStatus(currentStatus);
  activeRuleId = response?.ruleId || null;
  conflictRuleIds = response?.matchRuleIds || [];
  applyActiveRuleIndicators();
}

function createField(labelText, value, type = "text", inputClass = "", options = {}) {
  const field = document.createElement("label");
  field.className = "field";

  const label = document.createElement("span");
  label.textContent = labelText;

  const input = document.createElement("input");
  input.type = type;
  input.value = value || "";
  if (inputClass) {
    input.classList.add(inputClass);
  }

  const inputWrap = document.createElement("div");
  inputWrap.className = "field-input";
  inputWrap.append(input);
  if (options.action) {
    inputWrap.append(options.action);
  }

  field.append(label, inputWrap);
  return { field, input, inputWrap };
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

function buildSummaryLabel(nameValue, patternValue) {
  const name = nameValue ? nameValue.trim() : "";
  if (name) {
    return name;
  }
  const host = extractHost(patternValue);
  return host || "Custom rule";
}

function syncExpandedIds() {
  const ids = new Set(rules.map((rule) => rule.id));
  for (const id of expandedRuleIds) {
    if (!ids.has(id)) {
      expandedRuleIds.delete(id);
    }
  }
}

function applyActiveRuleIndicators() {
  const cards = rulesList.querySelectorAll(".rule-card");
  for (const card of cards) {
    const isActive = activeRuleId && card.dataset.ruleId === activeRuleId;
    const isConflict =
      currentStatus === "conflict" && conflictRuleIds.includes(card.dataset.ruleId);
    const isError = currentStatus === "auth_failed" && isActive;
    card.classList.toggle("is-active", Boolean(isActive) && !isError);
    card.classList.toggle("is-conflict", Boolean(isConflict));
    card.classList.toggle("is-error", Boolean(isError));
    const badge = card.querySelector(".active-badge");
    if (badge) {
      badge.hidden = !isActive || isError;
    }
    const conflictBadge = card.querySelector(".conflict-badge");
    if (conflictBadge) {
      conflictBadge.hidden = !isConflict;
    }
    const errorBadge = card.querySelector(".error-badge");
    if (errorBadge) {
      errorBadge.hidden = !isError;
    }
  }
}

async function updateRule(ruleId, patch) {
  rules = rules.map((rule) => (rule.id === ruleId ? { ...rule, ...patch } : rule));
  await saveRules(rules);
  renderRules();
  if (currentTab?.id && currentTab?.url) {
    chrome.runtime.sendMessage({
      type: "refreshTabStatus",
      tabId: currentTab.id,
      url: currentTab.url
    });
  }
}

async function removeRule(ruleId) {
  rules = rules.filter((rule) => rule.id !== ruleId);
  expandedRuleIds.delete(ruleId);
  await saveRules(rules);
  renderRules();
  if (currentTab?.id && currentTab?.url) {
    chrome.runtime.sendMessage({
      type: "refreshTabStatus",
      tabId: currentTab.id,
      url: currentTab.url
    });
  }
}

function createChevronIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.classList.add("rule-chevron");

  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M9 6l6 6-6 6");
  svg.append(path);

  return svg;
}

function createEyeIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");

  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute(
    "d",
    "M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z"
  );
  const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  circle.setAttribute("cx", "12");
  circle.setAttribute("cy", "12");
  circle.setAttribute("r", "3");

  svg.append(path, circle);
  return svg;
}

function escapePassword(value) {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/\t/g, "\\t")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r");
}

function unescapePassword(value) {
  const placeholder = "__BACKSLASH__";
  let result = value.replace(/\\\\/g, placeholder);
  result = result.replace(/\\t/g, "\t").replace(/\\n/g, "\n").replace(/\\r/g, "\r");
  return result.replace(new RegExp(placeholder, "g"), "\\");
}

function createRuleCard(rule) {
  const baseValues = {
    name: rule.name || "",
    pattern: rule.pattern || "",
    username: rule.username || "",
    password: rule.password || "",
    enabled: rule.enabled !== false
  };
  const isSynced = Boolean(rule.syncSourceId);

  const card = document.createElement("div");
  card.className = "rule-card";
  card.dataset.ruleId = rule.id;
  if (isSynced) {
    card.classList.add("is-synced");
  }

  const summary = document.createElement("div");
  summary.className = "rule-summary";
  summary.setAttribute("role", "button");
  summary.tabIndex = 0;

  const handle = document.createElement("span");
  handle.className = "rule-handle";
  handle.textContent = "::";
  handle.title = "Drag to reorder";

  const summaryText = document.createElement("div");
  summaryText.className = "rule-summary-text";

  const hostLine = document.createElement("div");
  hostLine.className = "summary-host";
  const hostText = document.createElement("span");
  const dirtyIndicator = document.createElement("span");
  dirtyIndicator.className = "dirty-indicator";
  dirtyIndicator.textContent = " *";
  dirtyIndicator.hidden = true;
  const activeBadge = document.createElement("span");
  activeBadge.className = "active-badge";
  activeBadge.textContent = "Active";
  activeBadge.hidden = true;
  const conflictBadge = document.createElement("span");
  conflictBadge.className = "conflict-badge";
  conflictBadge.textContent = "Conflict";
  conflictBadge.hidden = true;
  const errorBadge = document.createElement("span");
  errorBadge.className = "error-badge";
  errorBadge.textContent = "Error";
  errorBadge.hidden = true;
  const syncBadge = document.createElement("span");
  syncBadge.className = "sync-badge";
  syncBadge.textContent = "Sync";
  syncBadge.hidden = !isSynced;
  hostLine.append(hostText, dirtyIndicator, activeBadge, conflictBadge, errorBadge, syncBadge);

  const userSpan = document.createElement("span");
  userSpan.className = "summary-user";

  summaryText.append(hostLine, userSpan);

  const enabledLabel = document.createElement("label");
  enabledLabel.className = "rule-enabled";
  const enabledInput = document.createElement("input");
  enabledInput.type = "checkbox";
  enabledInput.checked = baseValues.enabled;
  enabledLabel.append(enabledInput, document.createTextNode("Enabled"));

  const chevron = createChevronIcon();

  summary.append(handle, summaryText, enabledLabel, chevron);

  const details = document.createElement("div");
  details.className = "rule-details";

  const { field: nameField, input: nameInput } = createField(
    "Label",
    baseValues.name,
    "text",
    "rule-name-input"
  );

  const { field: patternField, input: patternInput } = createField(
    "Pattern",
    baseValues.pattern,
    "text",
    "rule-pattern"
  );
  const patternError = document.createElement("span");
  patternError.className = "field-error";
  patternError.textContent = "Invalid regex";
  patternError.hidden = true;

  const { field: userField, input: userInput } = createField(
    "Username",
    baseValues.username,
    "text",
    "rule-username"
  );

  const toggleButton = document.createElement("button");
  toggleButton.type = "button";
  toggleButton.className = "toggle-password";
  toggleButton.setAttribute("aria-label", "Show password");
  toggleButton.append(createEyeIcon());

  const { field: passField, input: passInput } = createField(
    "Password",
    baseValues.password,
    "password",
    "",
    { action: toggleButton }
  );
  passInput.value = escapePassword(baseValues.password);

  const footer = document.createElement("div");
  footer.className = "rule-footer";

  const saveButton = document.createElement("button");
  saveButton.type = "button";
  saveButton.className = "save-button";
  saveButton.textContent = "Save";
  saveButton.disabled = true;

  const deleteButton = document.createElement("button");
  deleteButton.type = "button";
  deleteButton.className = "delete-button";
  deleteButton.textContent = "Delete";
  deleteButton.addEventListener("click", () => removeRule(rule.id));

  footer.append(deleteButton, saveButton);

  patternField.append(patternError);
  details.append(nameField, patternField, userField, passField, footer);
  card.append(summary, details);

  const getCurrentValues = () => ({
    name: nameInput.value.trim(),
    pattern: patternInput.value.trim(),
    username: userInput.value,
    password: unescapePassword(passInput.value),
    enabled: enabledInput.checked
  });

  const isDirty = () => {
    const current = getCurrentValues();
    return (
      current.name !== baseValues.name ||
      current.pattern !== baseValues.pattern ||
      current.username !== baseValues.username ||
      current.password !== baseValues.password
    );
  };

  const validatePattern = () => {
    const value = patternInput.value.trim();
    const valid = isValidRegex(value);
    patternInput.classList.toggle("invalid", !valid);
    patternError.hidden = valid;
    return valid;
  };

  const updateSummary = () => {
    const current = getCurrentValues();
    hostText.textContent = buildSummaryLabel(current.name, current.pattern);
    userSpan.textContent = current.username ? `User: ${current.username}` : "No username";
    card.classList.toggle("is-disabled", !current.enabled);
  };

  const updateDirtyState = () => {
    const dirty = isDirty();
    dirtyIndicator.hidden = !dirty;
    saveButton.disabled = !dirty;
    updateSummary();
  };

  const resetFields = () => {
    nameInput.value = baseValues.name;
    patternInput.value = baseValues.pattern;
    userInput.value = baseValues.username;
    passInput.value = escapePassword(baseValues.password);
    passInput.type = "password";
    toggleButton.classList.remove("is-visible");
    toggleButton.setAttribute("aria-label", "Show password");
    enabledInput.checked = baseValues.enabled;
    validatePattern();
    updateDirtyState();
  };

  const handleInputChange = () => {
    updateDirtyState();
  };

  if (!isSynced) {
    nameInput.addEventListener("input", handleInputChange);
    patternInput.addEventListener("input", () => {
      validatePattern();
      handleInputChange();
    });
    userInput.addEventListener("input", handleInputChange);
    passInput.addEventListener("input", handleInputChange);
  }
  toggleButton.addEventListener("click", () => {
    const revealed = passInput.type === "text";
    passInput.type = revealed ? "password" : "text";
    toggleButton.classList.toggle("is-visible", !revealed);
    toggleButton.setAttribute("aria-label", revealed ? "Show password" : "Hide password");
  });
  enabledInput.addEventListener("change", async () => {
    const enabled = enabledInput.checked;
    baseValues.enabled = enabled;
    rules = rules.map((item) => (item.id === rule.id ? { ...item, enabled } : item));
    await saveRules(rules);
    updateSummary();
    updateDirtyState();
    if (currentTab?.id && currentTab?.url) {
      chrome.runtime.sendMessage({
        type: "refreshTabStatus",
        tabId: currentTab.id,
        url: currentTab.url
      });
    }
  });

  if (!isSynced) {
    saveButton.addEventListener("click", async () => {
      if (!validatePattern()) {
        return;
      }
      const current = getCurrentValues();
      await updateRule(rule.id, current);
    });
  }

  const isExpanded = expandedRuleIds.has(rule.id);
  const setExpanded = (expanded) => {
    card.classList.toggle("expanded", expanded);
    summary.setAttribute("aria-expanded", String(expanded));
  };
  setExpanded(isExpanded);

  const toggleExpanded = () => {
    const nextExpanded = !card.classList.contains("expanded");
    if (nextExpanded) {
      expandedRuleIds.add(rule.id);
    } else {
      expandedRuleIds.delete(rule.id);
      resetFields();
    }
    setExpanded(nextExpanded);
  };

  summary.addEventListener("click", (event) => {
    if (
      event.target.closest("input") ||
      event.target.closest("label") ||
      event.target.closest(".rule-handle")
    ) {
      return;
    }
    toggleExpanded();
  });

  summary.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggleExpanded();
    }
  });

  if (isSynced) {
    nameInput.disabled = true;
    patternInput.disabled = true;
    userInput.disabled = true;
    passInput.disabled = true;
    saveButton.hidden = true;
    deleteButton.hidden = true;
    dirtyIndicator.hidden = true;
  }

  updateSummary();
  const isActive = rule.id === activeRuleId;
  const isError = currentStatus === "auth_failed" && isActive;
  const isConflict = currentStatus === "conflict" && conflictRuleIds.includes(rule.id);
  card.classList.toggle("is-active", isActive && !isError);
  card.classList.toggle("is-error", isError);
  card.classList.toggle("is-conflict", isConflict);
  activeBadge.hidden = !isActive || isError;
  errorBadge.hidden = !isError;
  conflictBadge.hidden = !isConflict;
  return card;
}

function renderRules() {
  syncExpandedIds();
  rulesList.innerHTML = "";
  ruleCount.textContent = String(rules.length);
  emptyState.style.display = rules.length ? "none" : "block";

  for (const rule of rules) {
    rulesList.append(createRuleCard(rule));
  }

  initSortable();
  applyActiveRuleIndicators();

  if (pendingFocus) {
    const focusInput = rulesList.querySelector(
      `[data-rule-id="${pendingFocus.id}"] ${pendingFocus.selector}`
    );
    if (focusInput) {
      focusInput.focus();
    }
    pendingFocus = null;
  }
}

async function addRule() {
  const url = currentTab?.url || "";
  const pattern = url ? buildDefaultPattern(url) : "";
  const hostLabel = (() => {
    if (!url) {
      return "Custom rule";
    }
    try {
      return new URL(url).host;
    } catch (error) {
      return "Custom rule";
    }
  })();
  const newRule = {
    id: generateId(),
    name: hostLabel,
    pattern,
    username: "",
    password: "",
    enabled: true,
    createdAt: Date.now()
  };
  rules = [newRule, ...rules];
  expandedRuleIds.add(newRule.id);
  pendingFocus = { id: newRule.id, selector: ".rule-username" };
  await saveRules(rules);
  renderRules();
  if (currentTab?.id) {
    chrome.runtime.sendMessage({
      type: "refreshTabStatus",
      tabId: currentTab.id,
      url: currentTab.url
    });
  }
}

async function loadRules() {
  rules = await getRules();
  renderRules();
}

function initSortable() {
  if (sortableInstance || !window.Sortable) {
    return;
  }
  sortableInstance = new window.Sortable(rulesList, {
    animation: 150,
    handle: ".rule-handle",
    draggable: ".rule-card",
    onEnd: async () => {
      const orderedIds = Array.from(rulesList.children)
        .map((child) => child.dataset.ruleId)
        .filter(Boolean);
      const nextRules = orderedIds
        .map((id) => rules.find((rule) => rule.id === id))
        .filter(Boolean);
      if (nextRules.length !== rules.length) {
        return;
      }
      rules = nextRules;
      await saveRules(rules);
      if (currentTab?.id && currentTab?.url) {
        chrome.runtime.sendMessage({
          type: "refreshTabStatus",
          tabId: currentTab.id,
          url: currentTab.url
        });
      }
    }
  });
}

async function init() {
  const tabs = await queryTabs({ active: true, currentWindow: true });
  currentTab = tabs[0] || null;
  if (versionLabel) {
    const manifest = chrome.runtime.getManifest();
    versionLabel.textContent = `v${manifest.version}`;
  }
  await loadRules();
  await refreshStatus();
}

addRuleButton.addEventListener("click", addRule);
openOptionsButton.addEventListener("click", () => chrome.runtime.openOptionsPage());

chrome.runtime.onMessage.addListener((message) => {
  if (!message || message.type !== "tabStatusChanged") {
    return;
  }
  if (message.tabId === currentTab?.id) {
    currentStatus = message.status || "idle";
    updateStatus(currentStatus);
    activeRuleId = message.ruleId || null;
    conflictRuleIds = message.matchRuleIds || [];
    applyActiveRuleIndicators();
  }
});

init();
