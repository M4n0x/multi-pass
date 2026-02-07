import { STATUS, BADGE_CONFIG } from "./shared/constants.js";

const RULES_KEY = "rules";
const VAULT_PAYLOAD_KEY = "vaultPayload";
const VAULT_SESSION_KEY = "vaultSessionKeyV1";
const VAULT_VERSION = 1;
const VAULT_KDF_ITERATIONS = 210000;

const tabStatus = new Map();
const requestMeta = new Map();

let rulesCache = [];
let vaultPayload = null;
let vaultSessionKey = null;
let vaultUnlocked = false;
let initPromise = null;

function setBadge(tabId, state) {
  if (tabId < 0) {
    return;
  }
  const config = BADGE_CONFIG[state] || BADGE_CONFIG.idle;
  chrome.action.setBadgeBackgroundColor({ tabId, color: config.color });
  chrome.action.setBadgeTextColor({ tabId, color: "#FFFFFF" });
  chrome.action.setBadgeText({ tabId, text: config.text });
}

function notifyTabStatus(tabId) {
  const current = tabStatus.get(tabId);
  const state = current ? current.state : STATUS.IDLE;
  const ruleId = current ? current.ruleId : null;
  const matchRuleIds = current ? current.matchRuleIds || [] : [];
  chrome.runtime
    .sendMessage({ type: "tabStatusChanged", tabId, status: state, ruleId, matchRuleIds })
    .catch(() => {
      return;
    });
}

function setTabStatus(tabId, state, ruleId, url, matchRuleIds = []) {
  if (tabId < 0) {
    return;
  }
  const existing = tabStatus.get(tabId);
  if (
    existing &&
    existing.state === state &&
    existing.ruleId === ruleId &&
    existing.url === url
  ) {
    return;
  }
  tabStatus.set(tabId, {
    state,
    ruleId,
    url,
    matchRuleIds,
    updatedAt: Date.now()
  });
  setBadge(tabId, state);
  notifyTabStatus(tabId);
}

function compileRegex(pattern) {
  try {
    return new RegExp(pattern);
  } catch (error) {
    return null;
  }
}

function matchRules(rules, url) {
  const matches = [];
  for (const rule of rules) {
    if (!rule || !rule.enabled) {
      continue;
    }
    if (!rule.pattern || typeof rule.pattern !== "string") {
      continue;
    }
    const regex = compileRegex(rule.pattern);
    if (!regex) {
      continue;
    }
    if (regex.test(url)) {
      matches.push(rule);
    }
  }
  return matches;
}

function selectRule(matches) {
  return matches[0];
}

function shouldKeepAuthFailed(tabId, ruleId) {
  if (!ruleId) {
    return false;
  }
  const existing = tabStatus.get(tabId);
  return Boolean(existing && existing.state === STATUS.AUTH_FAILED && existing.ruleId === ruleId);
}

function localGet(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (items) => resolve(items || {}));
  });
}

function localSet(values) {
  return new Promise((resolve) => {
    chrome.storage.local.set(values, () => resolve());
  });
}

function localRemove(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.remove(keys, () => resolve());
  });
}

function sessionGet(keys) {
  if (!chrome.storage.session) {
    return Promise.resolve({});
  }
  return new Promise((resolve) => {
    chrome.storage.session.get(keys, (items) => resolve(items || {}));
  });
}

function sessionSet(values) {
  if (!chrome.storage.session) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    chrome.storage.session.set(values, () => resolve());
  });
}

function sessionRemove(keys) {
  if (!chrome.storage.session) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    chrome.storage.session.remove(keys, () => resolve());
  });
}

function cloneRules(rules) {
  return JSON.parse(JSON.stringify(Array.isArray(rules) ? rules : []));
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function isVaultEnabled() {
  return Boolean(vaultPayload);
}

function getVaultStatePayload() {
  return {
    supported: true,
    enabled: isVaultEnabled(),
    unlocked: !isVaultEnabled() || vaultUnlocked
  };
}

function isValidVaultPayload(payload) {
  return Boolean(
    payload &&
      payload.version === VAULT_VERSION &&
      payload.kdf &&
      Number.isInteger(payload.kdf.iterations) &&
      payload.kdf.iterations > 0 &&
      typeof payload.kdf.salt === "string" &&
      payload.ciphertext &&
      typeof payload.ciphertext.iv === "string" &&
      typeof payload.ciphertext.data === "string"
  );
}

async function deriveKeyFromPassword(password, saltBase64, iterations) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: base64ToBytes(saltBase64),
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function exportSessionKey(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bytesToBase64(new Uint8Array(raw));
}

async function importSessionKey(rawBase64) {
  return crypto.subtle.importKey(
    "raw",
    base64ToBytes(rawBase64),
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptRulesWithKey(rules, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(cloneRules(rules)));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return {
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted))
  };
}

async function decryptRulesWithKey(payload, key) {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(payload.ciphertext.iv)
    },
    key,
    base64ToBytes(payload.ciphertext.data)
  );
  const text = new TextDecoder().decode(decrypted);
  const parsed = JSON.parse(text);
  return Array.isArray(parsed) ? parsed : [];
}

async function persistSessionKey(key) {
  if (!chrome.storage.session) {
    return;
  }
  const raw = await exportSessionKey(key);
  await sessionSet({ [VAULT_SESSION_KEY]: raw });
}

async function clearPersistedSessionKey() {
  await sessionRemove(VAULT_SESSION_KEY);
}

async function lockVault({ clearSession = true } = {}) {
  vaultUnlocked = false;
  vaultSessionKey = null;
  rulesCache = [];
  if (clearSession) {
    await clearPersistedSessionKey();
  }
}

async function loadPlainRules() {
  const result = await localGet([RULES_KEY]);
  return Array.isArray(result[RULES_KEY]) ? result[RULES_KEY] : [];
}

async function saveVaultRules(rules) {
  if (!vaultSessionKey || !vaultPayload) {
    throw new Error("Vault is locked");
  }
  const ciphertext = await encryptRulesWithKey(rules, vaultSessionKey);
  vaultPayload = {
    ...vaultPayload,
    ciphertext,
    updatedAt: Date.now()
  };
  await localSet({ [VAULT_PAYLOAD_KEY]: vaultPayload });
  rulesCache = cloneRules(rules);
  return rulesCache;
}

async function tryRestoreSession() {
  if (!isVaultEnabled()) {
    return false;
  }
  if (!chrome.storage.session) {
    return false;
  }
  const result = await sessionGet([VAULT_SESSION_KEY]);
  const raw = result[VAULT_SESSION_KEY];
  if (!raw || typeof raw !== "string") {
    return false;
  }
  try {
    const key = await importSessionKey(raw);
    const rules = await decryptRulesWithKey(vaultPayload, key);
    vaultSessionKey = key;
    vaultUnlocked = true;
    rulesCache = cloneRules(rules);
    return true;
  } catch (error) {
    await clearPersistedSessionKey();
    return false;
  }
}

async function initializeState() {
  const result = await localGet([RULES_KEY, VAULT_PAYLOAD_KEY]);
  const payload = result[VAULT_PAYLOAD_KEY];
  vaultPayload = isValidVaultPayload(payload) ? payload : null;

  if (!isVaultEnabled()) {
    vaultUnlocked = true;
    vaultSessionKey = null;
    rulesCache = Array.isArray(result[RULES_KEY]) ? result[RULES_KEY] : [];
    await clearPersistedSessionKey();
    return;
  }

  vaultUnlocked = false;
  vaultSessionKey = null;
  rulesCache = [];
  await tryRestoreSession();
}

async function ensureInitialized() {
  if (!initPromise) {
    initPromise = initializeState().catch((error) => {
      initPromise = null;
      throw error;
    });
  }
  await initPromise;
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8;
}

async function enableVault(password) {
  await ensureInitialized();
  if (!validatePassword(password)) {
    return { ok: false, error: "weak-password" };
  }
  if (isVaultEnabled()) {
    return { ok: false, error: "already-enabled" };
  }

  const plainRules = await loadPlainRules();
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = bytesToBase64(saltBytes);
  const key = await deriveKeyFromPassword(password, salt, VAULT_KDF_ITERATIONS);
  const ciphertext = await encryptRulesWithKey(plainRules, key);

  vaultPayload = {
    version: VAULT_VERSION,
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: VAULT_KDF_ITERATIONS,
      salt
    },
    ciphertext,
    updatedAt: Date.now()
  };

  await localSet({ [VAULT_PAYLOAD_KEY]: vaultPayload });
  await localRemove(RULES_KEY);

  vaultSessionKey = key;
  vaultUnlocked = true;
  rulesCache = cloneRules(plainRules);
  await persistSessionKey(key);
  await refreshAllTabs();

  return { ok: true };
}

async function unlockVault(password) {
  await ensureInitialized();
  if (!isVaultEnabled()) {
    return { ok: false, error: "not-enabled" };
  }
  if (vaultUnlocked) {
    return { ok: true };
  }
  if (!validatePassword(password)) {
    return { ok: false, error: "invalid-password" };
  }

  try {
    const key = await deriveKeyFromPassword(
      password,
      vaultPayload.kdf.salt,
      vaultPayload.kdf.iterations
    );
    const rules = await decryptRulesWithKey(vaultPayload, key);
    vaultSessionKey = key;
    vaultUnlocked = true;
    rulesCache = cloneRules(rules);
    await persistSessionKey(key);
    await refreshAllTabs();
    return { ok: true };
  } catch (error) {
    return { ok: false, error: "invalid-password" };
  }
}

async function disableVault() {
  await ensureInitialized();
  if (!isVaultEnabled()) {
    return { ok: false, error: "not-enabled" };
  }
  if (!vaultUnlocked) {
    return { ok: false, error: "locked" };
  }

  const plainRules = cloneRules(rulesCache);
  await localSet({ [RULES_KEY]: plainRules });
  await localRemove(VAULT_PAYLOAD_KEY);

  vaultPayload = null;
  vaultSessionKey = null;
  vaultUnlocked = true;
  rulesCache = plainRules;
  await clearPersistedSessionKey();
  await refreshAllTabs();

  return { ok: true };
}

async function changeVaultPassword(currentPassword, nextPassword) {
  await ensureInitialized();
  if (!isVaultEnabled()) {
    return { ok: false, error: "not-enabled" };
  }
  if (!validatePassword(nextPassword)) {
    return { ok: false, error: "weak-password" };
  }

  try {
    const currentKey = await deriveKeyFromPassword(
      currentPassword,
      vaultPayload.kdf.salt,
      vaultPayload.kdf.iterations
    );
    const rules = await decryptRulesWithKey(vaultPayload, currentKey);

    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const salt = bytesToBase64(saltBytes);
    const nextKey = await deriveKeyFromPassword(nextPassword, salt, VAULT_KDF_ITERATIONS);
    const ciphertext = await encryptRulesWithKey(rules, nextKey);

    vaultPayload = {
      version: VAULT_VERSION,
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: VAULT_KDF_ITERATIONS,
        salt
      },
      ciphertext,
      updatedAt: Date.now()
    };

    await localSet({ [VAULT_PAYLOAD_KEY]: vaultPayload });
    vaultSessionKey = nextKey;
    vaultUnlocked = true;
    rulesCache = cloneRules(rules);
    await persistSessionKey(nextKey);
    await refreshAllTabs();

    return { ok: true };
  } catch (error) {
    return { ok: false, error: "invalid-password" };
  }
}

async function lockVaultAndRefresh() {
  await ensureInitialized();
  if (!isVaultEnabled()) {
    return { ok: true };
  }
  await lockVault({ clearSession: true });
  await refreshAllTabs();
  return { ok: true };
}

async function updateTabStatusForUrl(tabId, url) {
  await ensureInitialized();
  if (tabId < 0) {
    return;
  }

  if (isVaultEnabled() && !vaultUnlocked) {
    setTabStatus(tabId, STATUS.LOCKED, null, url || "", []);
    return;
  }

  if (!url || !url.startsWith("http")) {
    setTabStatus(tabId, STATUS.IDLE, null, url || "");
    return;
  }

  const matches = matchRules(rulesCache, url);
  if (matches.length === 0) {
    setTabStatus(tabId, STATUS.IDLE, null, url, []);
    return;
  }
  if (matches.length > 1) {
    const selected = selectRule(matches);
    setTabStatus(
      tabId,
      STATUS.CONFLICT,
      selected?.id || null,
      url,
      matches.map((rule) => rule.id).filter(Boolean)
    );
    return;
  }
  const selected = matches[0];
  if (shouldKeepAuthFailed(tabId, selected?.id)) {
    setTabStatus(
      tabId,
      STATUS.AUTH_FAILED,
      selected?.id || null,
      url,
      [selected?.id].filter(Boolean)
    );
    return;
  }
  setTabStatus(tabId, STATUS.OK, selected?.id || null, url, [selected?.id].filter(Boolean));
}

async function handleAuth(details) {
  await ensureInitialized();
  const tabId = details.tabId;
  const url = details.url || "";
  if (tabId < 0 || details.isProxy) {
    return {};
  }
  if (details.scheme && details.scheme.toLowerCase() !== "basic") {
    return {};
  }

  if (isVaultEnabled() && !vaultUnlocked) {
    setTabStatus(tabId, STATUS.LOCKED, null, url, []);
    return {};
  }

  const matches = matchRules(rulesCache, url);
  if (matches.length === 0) {
    setTabStatus(tabId, STATUS.IDLE, null, url, []);
    return {};
  }

  const selected = selectRule(matches);
  const hasConflict = matches.length > 1;

  if (shouldKeepAuthFailed(tabId, selected?.id)) {
    return {};
  }

  const requestId = details.requestId;
  const existing = requestMeta.get(requestId);

  if (existing) {
    existing.attempts += 1;
    if (!existing.conflict) {
      setTabStatus(
        tabId,
        STATUS.AUTH_FAILED,
        selected?.id || null,
        url,
        [selected?.id].filter(Boolean)
      );
    }
    return {};
  }

  requestMeta.set(requestId, {
    tabId,
    ruleId: selected?.id || null,
    attempts: 0,
    conflict: hasConflict
  });

  if (hasConflict) {
    setTabStatus(
      tabId,
      STATUS.CONFLICT,
      selected?.id || null,
      url,
      matches.map((rule) => rule.id).filter(Boolean)
    );
  } else {
    setTabStatus(tabId, STATUS.OK, selected?.id || null, url, [selected?.id].filter(Boolean));
  }

  return {
    authCredentials: {
      username: selected?.username || "",
      password: selected?.password || ""
    }
  };
}

chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    handleAuth(details)
      .then((response) => callback(response))
      .catch(() => callback({}));
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"]
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    const meta = requestMeta.get(details.requestId);
    if (!meta) {
      return;
    }
    if (!meta.conflict) {
      if (details.statusCode === 401) {
        setTabStatus(
          meta.tabId,
          STATUS.AUTH_FAILED,
          meta.ruleId,
          details.url,
          [meta.ruleId].filter(Boolean)
        );
      } else {
        setTabStatus(meta.tabId, STATUS.OK, meta.ruleId, details.url, [meta.ruleId].filter(Boolean));
      }
    }
    requestMeta.delete(details.requestId);
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    const meta = requestMeta.get(details.requestId);
    if (!meta) {
      return;
    }
    if (!meta.conflict) {
      setTabStatus(
        meta.tabId,
        STATUS.AUTH_FAILED,
        meta.ruleId,
        details.url,
        [meta.ruleId].filter(Boolean)
      );
    }
    requestMeta.delete(details.requestId);
  },
  { urls: ["<all_urls>"] }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") {
    return false;
  }

  if (message.type === "getTabStatus") {
    const status = tabStatus.get(message.tabId) || {
      state: isVaultEnabled() && !vaultUnlocked ? STATUS.LOCKED : STATUS.IDLE
    };
    sendResponse({
      status: status.state,
      ruleId: status.ruleId || null,
      matchRuleIds: status.matchRuleIds || []
    });
    return true;
  }

  if (message.type === "refreshTabStatus") {
    updateTabStatusForUrl(message.tabId, message.url).catch(() => {
      return;
    });
    return false;
  }

  if (message.type === "clearAuthFailed") {
    const ruleId = message.ruleId;
    for (const [tabId, status] of tabStatus.entries()) {
      if (status.state === STATUS.AUTH_FAILED && status.ruleId === ruleId) {
        tabStatus.delete(tabId);
      }
    }
    return false;
  }

  if (message.type === "getVaultState") {
    ensureInitialized()
      .then(() => sendResponse(getVaultStatePayload()))
      .catch(() => sendResponse({ supported: true, enabled: false, unlocked: true }));
    return true;
  }

  if (message.type === "unlockVault") {
    unlockVault(message.password)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "unlock-failed" }));
    return true;
  }

  if (message.type === "lockVault") {
    lockVaultAndRefresh()
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "lock-failed" }));
    return true;
  }

  if (message.type === "enableVault") {
    enableVault(message.password)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "enable-failed" }));
    return true;
  }

  if (message.type === "disableVault") {
    disableVault()
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "disable-failed" }));
    return true;
  }

  if (message.type === "changeVaultPassword") {
    changeVaultPassword(message.currentPassword, message.nextPassword)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "change-password-failed" }));
    return true;
  }

  if (message.type === "vaultGetRules") {
    ensureInitialized()
      .then(() => {
        if (isVaultEnabled() && !vaultUnlocked) {
          sendResponse({ locked: true });
          return;
        }
        sendResponse({ locked: false, rules: cloneRules(rulesCache) });
      })
      .catch(() => sendResponse({ locked: true }));
    return true;
  }

  if (message.type === "vaultSaveRules") {
    ensureInitialized()
      .then(async () => {
        const nextRules = Array.isArray(message.rules) ? message.rules : [];
        if (isVaultEnabled()) {
          if (!vaultUnlocked) {
            sendResponse({ ok: false, locked: true });
            return;
          }
          const saved = await saveVaultRules(nextRules);
          sendResponse({ ok: true, locked: false, rules: saved });
          await refreshAllTabs();
          return;
        }
        await localSet({ [RULES_KEY]: nextRules });
        rulesCache = cloneRules(nextRules);
        sendResponse({ ok: true, locked: false, rules: cloneRules(rulesCache) });
        await refreshAllTabs();
      })
      .catch(() => sendResponse({ ok: false, error: "save-failed" }));
    return true;
  }

  return false;
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab?.url) {
      updateTabStatusForUrl(tabId, tab.url);
    }
  } catch (error) {
    return;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    updateTabStatusForUrl(tabId, changeInfo.url);
    return;
  }
  if (changeInfo.status === "complete" && tab?.url) {
    updateTabStatusForUrl(tabId, tab.url);
    const current = tabStatus.get(tabId);
    if (current) {
      setBadge(tabId, current.state);
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStatus.delete(tabId);
  for (const [requestId, meta] of requestMeta.entries()) {
    if (meta.tabId === tabId) {
      requestMeta.delete(requestId);
    }
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") {
    return;
  }

  if (changes[VAULT_PAYLOAD_KEY]) {
    const nextPayload = changes[VAULT_PAYLOAD_KEY].newValue;
    vaultPayload = isValidVaultPayload(nextPayload) ? nextPayload : null;

    if (!isVaultEnabled()) {
      vaultUnlocked = true;
      vaultSessionKey = null;
      rulesCache = Array.isArray(changes[RULES_KEY]?.newValue)
        ? changes[RULES_KEY].newValue
        : rulesCache;
      clearPersistedSessionKey();
      refreshAllTabs();
      return;
    }

    if (vaultSessionKey) {
      decryptRulesWithKey(vaultPayload, vaultSessionKey)
        .then((rules) => {
          vaultUnlocked = true;
          rulesCache = cloneRules(rules);
          refreshAllTabs();
        })
        .catch(async () => {
          await lockVault({ clearSession: true });
          refreshAllTabs();
        });
      return;
    }

    vaultUnlocked = false;
    rulesCache = [];
    refreshAllTabs();
    return;
  }

  if (!isVaultEnabled() && changes[RULES_KEY]) {
    rulesCache = Array.isArray(changes[RULES_KEY].newValue) ? changes[RULES_KEY].newValue : [];
    refreshAllTabs();
  }
});

async function refreshAllTabs() {
  await ensureInitialized();
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (tab.id != null && tab.url) {
      updateTabStatusForUrl(tab.id, tab.url);
    }
  }
}

chrome.runtime.onInstalled.addListener(() => {
  ensureInitialized()
    .then(() => refreshAllTabs())
    .catch(() => {
      return;
    });
});

chrome.runtime.onStartup.addListener(() => {
  ensureInitialized()
    .then(() => refreshAllTabs())
    .catch(() => {
      return;
    });
});

ensureInitialized()
  .then(() => refreshAllTabs())
  .catch(() => {
    return;
  });
