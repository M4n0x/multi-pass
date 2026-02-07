import { STATUS, BADGE_CONFIG } from "./shared/constants.js";

const RULES_KEY = "rules";
const VAULT_PAYLOAD_KEY = "vaultPayload";
const VAULT_SESSION_KEY = "vaultSessionKeyV1";
const VAULT_PERSISTENT_KEY = "vaultPersistentSessionKeyV1";
const VAULT_SETTINGS_KEY = "vaultSettings";
const VAULT_WEBAUTHN_KEY = "vaultWebAuthnV1";
const VAULT_VERSION = 1;
const VAULT_KDF_ITERATIONS = 210000;
const WEBAUTHN_VERSION = 1;
const WEBAUTHN_CHALLENGE_TIMEOUT_MS = 2 * 60 * 1000;
const DEFAULT_VAULT_SETTINGS = {
  lockOnBrowserClose: true
};

const tabStatus = new Map();
const requestMeta = new Map();

let rulesCache = [];
let vaultPayload = null;
let vaultSessionKey = null;
let vaultUnlocked = false;
let vaultSettings = { ...DEFAULT_VAULT_SETTINGS };
let vaultWebAuthn = null;
let pendingWebAuthnSetup = null;
let pendingWebAuthnUnlock = null;
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

function base64UrlToBytes(value) {
  if (typeof value !== "string") {
    return new Uint8Array();
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4;
  const padded = padding === 0 ? normalized : `${normalized}${"=".repeat(4 - padding)}`;
  return base64ToBytes(padded);
}

function bytesEqual(left, right) {
  if (!left || !right || left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) {
      return false;
    }
  }
  return true;
}

function normalizeVaultSettings(raw) {
  return {
    lockOnBrowserClose:
      typeof raw?.lockOnBrowserClose === "boolean"
        ? raw.lockOnBrowserClose
        : DEFAULT_VAULT_SETTINGS.lockOnBrowserClose
  };
}

function isVaultEnabled() {
  return Boolean(vaultPayload);
}

function getVaultStatePayload() {
  return {
    supported: true,
    enabled: isVaultEnabled(),
    unlocked: !isVaultEnabled() || vaultUnlocked,
    lockOnBrowserClose: Boolean(vaultSettings.lockOnBrowserClose)
  };
}

function getVaultSettingsPayload() {
  return {
    supported: true,
    lockOnBrowserClose: Boolean(vaultSettings.lockOnBrowserClose)
  };
}

function isValidVaultWebAuthnPayload(payload) {
  return Boolean(
    payload &&
      payload.version === WEBAUTHN_VERSION &&
      typeof payload.credentialId === "string" &&
      payload.credentialId &&
      typeof payload.prfSalt === "string" &&
      payload.wrappedSessionKey &&
      typeof payload.wrappedSessionKey.iv === "string" &&
      typeof payload.wrappedSessionKey.data === "string"
  );
}

function getVaultWebAuthnStatePayload() {
  return {
    supported: true,
    available: isVaultEnabled(),
    configured: isValidVaultWebAuthnPayload(vaultWebAuthn)
  };
}

function clearPendingWebAuthnRequests() {
  pendingWebAuthnSetup = null;
  pendingWebAuthnUnlock = null;
}

function clearExpiredWebAuthnRequests() {
  const now = Date.now();
  if (
    pendingWebAuthnSetup &&
    now - pendingWebAuthnSetup.createdAt > WEBAUTHN_CHALLENGE_TIMEOUT_MS
  ) {
    pendingWebAuthnSetup = null;
  }
  if (
    pendingWebAuthnUnlock &&
    now - pendingWebAuthnUnlock.createdAt > WEBAUTHN_CHALLENGE_TIMEOUT_MS
  ) {
    pendingWebAuthnUnlock = null;
  }
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

async function encryptStringWithKey(value, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(String(value));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return {
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted))
  };
}

async function decryptStringWithKey(ciphertext, key) {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(ciphertext.iv)
    },
    key,
    base64ToBytes(ciphertext.data)
  );
  return new TextDecoder().decode(decrypted);
}

async function deriveWebAuthnWrapKey(prfOutputBase64, prfSaltBase64) {
  const prfBytes = base64ToBytes(prfOutputBase64);
  const saltBytes = base64ToBytes(prfSaltBase64);
  const combined = new Uint8Array(prfBytes.length + saltBytes.length);
  combined.set(prfBytes, 0);
  combined.set(saltBytes, prfBytes.length);
  const digest = await crypto.subtle.digest("SHA-256", combined);
  return crypto.subtle.importKey(
    "raw",
    digest,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

function parseClientData(clientDataBase64) {
  const bytes = base64ToBytes(clientDataBase64);
  const json = new TextDecoder().decode(bytes);
  return JSON.parse(json);
}

function isExpectedClientOrigin(origin) {
  if (typeof origin !== "string") {
    return false;
  }
  try {
    const runtimeOrigin = new URL(chrome.runtime.getURL("/")).origin;
    return origin === runtimeOrigin;
  } catch (error) {
    return false;
  }
}

function sanitizeCredentialDescriptor(descriptor) {
  if (!descriptor || typeof descriptor !== "object") {
    return null;
  }
  const credentialId =
    typeof descriptor.credentialId === "string"
      ? descriptor.credentialId
      : typeof descriptor.id === "string"
        ? descriptor.id
        : "";
  if (!credentialId) {
    return null;
  }
  return {
    id: credentialId,
    type: "public-key",
    transports: Array.isArray(descriptor.transports) ? descriptor.transports : undefined
  };
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
  const raw = await exportSessionKey(key);

  if (chrome.storage.session) {
    await sessionSet({ [VAULT_SESSION_KEY]: raw });
  }

  if (vaultSettings.lockOnBrowserClose) {
    await localRemove(VAULT_PERSISTENT_KEY);
    return;
  }

  await localSet({ [VAULT_PERSISTENT_KEY]: raw });
}

async function clearPersistedSessionKey() {
  await sessionRemove(VAULT_SESSION_KEY);
  await localRemove(VAULT_PERSISTENT_KEY);
}

async function lockVault({ clearSession = true } = {}) {
  vaultUnlocked = false;
  vaultSessionKey = null;
  rulesCache = [];
  clearPendingWebAuthnRequests();
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

  let raw = null;

  if (!vaultSettings.lockOnBrowserClose) {
    const persisted = await localGet([VAULT_PERSISTENT_KEY]);
    if (typeof persisted[VAULT_PERSISTENT_KEY] === "string") {
      raw = persisted[VAULT_PERSISTENT_KEY];
    }
  }

  if (!raw && chrome.storage.session) {
    const result = await sessionGet([VAULT_SESSION_KEY]);
    if (typeof result[VAULT_SESSION_KEY] === "string") {
      raw = result[VAULT_SESSION_KEY];
    }
  }

  if (!raw) {
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
  const result = await localGet([
    RULES_KEY,
    VAULT_PAYLOAD_KEY,
    VAULT_SETTINGS_KEY,
    VAULT_WEBAUTHN_KEY
  ]);
  const payload = result[VAULT_PAYLOAD_KEY];
  vaultPayload = isValidVaultPayload(payload) ? payload : null;
  vaultSettings = normalizeVaultSettings(result[VAULT_SETTINGS_KEY]);
  vaultWebAuthn = isValidVaultWebAuthnPayload(result[VAULT_WEBAUTHN_KEY])
    ? result[VAULT_WEBAUTHN_KEY]
    : null;

  if (!isVaultEnabled()) {
    vaultUnlocked = true;
    vaultSessionKey = null;
    rulesCache = Array.isArray(result[RULES_KEY]) ? result[RULES_KEY] : [];
    clearPendingWebAuthnRequests();
    await clearPersistedSessionKey();
    if (vaultWebAuthn) {
      await clearVaultWebAuthnConfig();
    }
    return;
  }

  vaultUnlocked = false;
  vaultSessionKey = null;
  rulesCache = [];
  clearPendingWebAuthnRequests();
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

async function clearVaultWebAuthnConfig() {
  vaultWebAuthn = null;
  clearPendingWebAuthnRequests();
  await localRemove(VAULT_WEBAUTHN_KEY);
}

function validateWebAuthnPrfOutput(prfOutput) {
  if (typeof prfOutput !== "string") {
    return false;
  }
  try {
    const bytes = base64ToBytes(prfOutput);
    return bytes.length >= 16;
  } catch (error) {
    return false;
  }
}

function validatePendingChallenge(clientDataJSONBase64, expectedChallengeBase64, expectedType) {
  try {
    const clientData = parseClientData(clientDataJSONBase64);
    if (clientData?.type !== expectedType) {
      return false;
    }
    if (!isExpectedClientOrigin(clientData?.origin)) {
      return false;
    }
    const clientChallenge = base64UrlToBytes(clientData?.challenge || "");
    const expectedChallenge = base64ToBytes(expectedChallengeBase64);
    return bytesEqual(clientChallenge, expectedChallenge);
  } catch (error) {
    return false;
  }
}

async function beginVaultWebAuthnSetup() {
  await ensureInitialized();
  clearExpiredWebAuthnRequests();

  if (!isVaultEnabled()) {
    return { ok: false, error: "not-enabled" };
  }
  if (!vaultUnlocked || !vaultSessionKey) {
    return { ok: false, error: "locked" };
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));

  pendingWebAuthnSetup = {
    challenge: bytesToBase64(challenge),
    prfSalt: bytesToBase64(prfSalt),
    createdAt: Date.now()
  };

  const excludeCredentials = vaultWebAuthn?.credentialId
    ? [sanitizeCredentialDescriptor(vaultWebAuthn)].filter(Boolean)
    : [];

  return {
    ok: true,
    options: {
      challenge: pendingWebAuthnSetup.challenge,
      userId: bytesToBase64(userId),
      rpName: "Multi-pass Vault",
      userName: "multi-pass-user",
      userDisplayName: "Multi-pass Vault",
      timeout: 90_000,
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 }
      ],
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "required",
      prfSalt: pendingWebAuthnSetup.prfSalt,
      excludeCredentials
    }
  };
}

async function completeVaultWebAuthnSetup(payload) {
  await ensureInitialized();
  clearExpiredWebAuthnRequests();

  if (!isVaultEnabled()) {
    return { ok: false, error: "not-enabled" };
  }
  if (!vaultUnlocked || !vaultSessionKey) {
    return { ok: false, error: "locked" };
  }
  if (!pendingWebAuthnSetup) {
    return { ok: false, error: "webauthn-session-expired" };
  }

  const localPending = pendingWebAuthnSetup;
  pendingWebAuthnSetup = null;

  try {
    if (
      !payload ||
      typeof payload !== "object" ||
      typeof payload.credentialId !== "string" ||
      typeof payload?.response?.clientDataJSON !== "string"
    ) {
      return { ok: false, error: "webauthn-invalid-response" };
    }

    if (!validateWebAuthnPrfOutput(payload.prfOutput)) {
      return { ok: false, error: "webauthn-prf-unavailable" };
    }

    const isValidChallenge = validatePendingChallenge(
      payload.response.clientDataJSON,
      localPending.challenge,
      "webauthn.create"
    );
    if (!isValidChallenge) {
      return { ok: false, error: "webauthn-invalid-response" };
    }

    const wrapKey = await deriveWebAuthnWrapKey(payload.prfOutput, localPending.prfSalt);
    const rawSessionKey = await exportSessionKey(vaultSessionKey);
    const wrappedSessionKey = await encryptStringWithKey(rawSessionKey, wrapKey);

    vaultWebAuthn = {
      version: WEBAUTHN_VERSION,
      credentialId: payload.credentialId,
      transports: Array.isArray(payload.transports) ? payload.transports : undefined,
      prfSalt: localPending.prfSalt,
      wrappedSessionKey,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    await localSet({ [VAULT_WEBAUTHN_KEY]: vaultWebAuthn });
    return { ok: true };
  } catch (error) {
    return { ok: false, error: "webauthn-setup-failed" };
  }
}

async function beginVaultWebAuthnUnlock() {
  await ensureInitialized();
  clearExpiredWebAuthnRequests();

  if (!isVaultEnabled()) {
    return { ok: false, error: "not-enabled" };
  }
  if (vaultUnlocked) {
    return { ok: true, alreadyUnlocked: true };
  }
  if (!isValidVaultWebAuthnPayload(vaultWebAuthn)) {
    return { ok: false, error: "webauthn-not-configured" };
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  pendingWebAuthnUnlock = {
    challenge: bytesToBase64(challenge),
    createdAt: Date.now()
  };

  return {
    ok: true,
    options: {
      challenge: pendingWebAuthnUnlock.challenge,
      timeout: 60_000,
      userVerification: "required",
      prfSalt: vaultWebAuthn.prfSalt,
      allowCredentials: [sanitizeCredentialDescriptor(vaultWebAuthn)].filter(Boolean)
    }
  };
}

async function completeVaultWebAuthnUnlock(payload) {
  await ensureInitialized();
  clearExpiredWebAuthnRequests();

  if (!isVaultEnabled()) {
    return { ok: false, error: "not-enabled" };
  }
  if (vaultUnlocked) {
    return { ok: true };
  }
  if (!isValidVaultWebAuthnPayload(vaultWebAuthn)) {
    return { ok: false, error: "webauthn-not-configured" };
  }
  if (!pendingWebAuthnUnlock) {
    return { ok: false, error: "webauthn-session-expired" };
  }

  const localPending = pendingWebAuthnUnlock;
  pendingWebAuthnUnlock = null;

  try {
    if (
      !payload ||
      typeof payload !== "object" ||
      payload.credentialId !== vaultWebAuthn.credentialId ||
      typeof payload?.response?.clientDataJSON !== "string"
    ) {
      return { ok: false, error: "webauthn-invalid-response" };
    }

    if (!validateWebAuthnPrfOutput(payload.prfOutput)) {
      return { ok: false, error: "webauthn-prf-unavailable" };
    }

    const isValidChallenge = validatePendingChallenge(
      payload.response.clientDataJSON,
      localPending.challenge,
      "webauthn.get"
    );
    if (!isValidChallenge) {
      return { ok: false, error: "webauthn-invalid-response" };
    }

    const wrapKey = await deriveWebAuthnWrapKey(payload.prfOutput, vaultWebAuthn.prfSalt);
    const rawSessionKey = await decryptStringWithKey(vaultWebAuthn.wrappedSessionKey, wrapKey);
    const key = await importSessionKey(rawSessionKey);
    const rules = await decryptRulesWithKey(vaultPayload, key);

    vaultSessionKey = key;
    vaultUnlocked = true;
    rulesCache = cloneRules(rules);
    await persistSessionKey(key);
    await refreshAllTabs();

    return { ok: true };
  } catch (error) {
    return { ok: false, error: "webauthn-unlock-failed" };
  }
}

async function disableVaultWebAuthn() {
  await ensureInitialized();
  if (!isVaultEnabled()) {
    return { ok: false, error: "not-enabled" };
  }
  if (!isValidVaultWebAuthnPayload(vaultWebAuthn)) {
    return { ok: true };
  }
  await clearVaultWebAuthnConfig();
  return { ok: true };
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
  await clearVaultWebAuthnConfig();

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
    if (isValidVaultWebAuthnPayload(vaultWebAuthn)) {
      await clearVaultWebAuthnConfig();
    }
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

async function setVaultLockOnClose(lockOnBrowserClose) {
  await ensureInitialized();
  vaultSettings = normalizeVaultSettings({ lockOnBrowserClose });
  await localSet({ [VAULT_SETTINGS_KEY]: vaultSettings });

  if (vaultSettings.lockOnBrowserClose) {
    await localRemove(VAULT_PERSISTENT_KEY);
    if (vaultSessionKey && chrome.storage.session) {
      const raw = await exportSessionKey(vaultSessionKey);
      await sessionSet({ [VAULT_SESSION_KEY]: raw });
    }
  } else if (vaultSessionKey) {
    const raw = await exportSessionKey(vaultSessionKey);
    await localSet({ [VAULT_PERSISTENT_KEY]: raw });
    if (chrome.storage.session) {
      await sessionSet({ [VAULT_SESSION_KEY]: raw });
    }
  }

  return { ok: true, lockOnBrowserClose: vaultSettings.lockOnBrowserClose };
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
      .catch(() =>
        sendResponse({
          supported: true,
          enabled: false,
          unlocked: true,
          lockOnBrowserClose: DEFAULT_VAULT_SETTINGS.lockOnBrowserClose
        })
      );
    return true;
  }

  if (message.type === "getVaultWebAuthnState") {
    ensureInitialized()
      .then(() => sendResponse(getVaultWebAuthnStatePayload()))
      .catch(() =>
        sendResponse({
          supported: false,
          available: false,
          configured: false
        })
      );
    return true;
  }

  if (message.type === "getVaultSettings") {
    ensureInitialized()
      .then(() => sendResponse({ ok: true, ...getVaultSettingsPayload() }))
      .catch(() =>
        sendResponse({
          ok: false,
          supported: true,
          lockOnBrowserClose: DEFAULT_VAULT_SETTINGS.lockOnBrowserClose
        })
      );
    return true;
  }

  if (message.type === "setVaultLockOnClose") {
    setVaultLockOnClose(message.lockOnBrowserClose)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "set-vault-setting-failed" }));
    return true;
  }

  if (message.type === "beginVaultWebAuthnSetup") {
    beginVaultWebAuthnSetup()
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "webauthn-setup-failed" }));
    return true;
  }

  if (message.type === "completeVaultWebAuthnSetup") {
    completeVaultWebAuthnSetup(message.payload)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "webauthn-setup-failed" }));
    return true;
  }

  if (message.type === "beginVaultWebAuthnUnlock") {
    beginVaultWebAuthnUnlock()
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "webauthn-unlock-failed" }));
    return true;
  }

  if (message.type === "completeVaultWebAuthnUnlock") {
    completeVaultWebAuthnUnlock(message.payload)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "webauthn-unlock-failed" }));
    return true;
  }

  if (message.type === "disableVaultWebAuthn") {
    disableVaultWebAuthn()
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false, error: "webauthn-disable-failed" }));
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

async function getNormalWindowCount() {
  try {
    const normalWindows = await chrome.windows.getAll({ windowTypes: ["normal"] });
    return normalWindows.length;
  } catch (error) {
    const windows = await chrome.windows.getAll({});
    return windows.filter((win) => !win.type || win.type === "normal").length;
  }
}

async function maybeLockVaultOnLastWindowClose() {
  await ensureInitialized();
  if (!vaultSettings.lockOnBrowserClose || !isVaultEnabled() || !vaultUnlocked) {
    return;
  }

  const normalWindowCount = await getNormalWindowCount();
  if (normalWindowCount === 0) {
    await lockVault({ clearSession: true });
  }
}

chrome.windows.onRemoved.addListener(() => {
  setTimeout(() => {
    maybeLockVaultOnLastWindowClose().catch(() => {
      return;
    });
  }, 150);
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") {
    return;
  }

  if (changes[VAULT_SETTINGS_KEY]) {
    vaultSettings = normalizeVaultSettings(changes[VAULT_SETTINGS_KEY].newValue);
  }

  if (changes[VAULT_WEBAUTHN_KEY]) {
    const nextWebAuthn = changes[VAULT_WEBAUTHN_KEY].newValue;
    vaultWebAuthn = isValidVaultWebAuthnPayload(nextWebAuthn) ? nextWebAuthn : null;
    if (!vaultWebAuthn) {
      clearPendingWebAuthnRequests();
    }
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
      clearPendingWebAuthnRequests();
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

async function enforceStartupLockIfNeeded() {
  await ensureInitialized();
  if (!isVaultEnabled() || !vaultSettings.lockOnBrowserClose) {
    return;
  }
  await lockVault({ clearSession: true });
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
    .then(() => enforceStartupLockIfNeeded())
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
