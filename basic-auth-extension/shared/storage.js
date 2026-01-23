const RULES_KEY = "rules";
const SYNC_SOURCES_KEY = "syncSources";

function storageGet(key) {
  const result = chrome.storage.local.get(key);
  if (result && typeof result.then === "function") {
    return result;
  }
  return new Promise((resolve) => {
    chrome.storage.local.get(key, (items) => resolve(items));
  });
}

function storageSet(values) {
  const result = chrome.storage.local.set(values);
  if (result && typeof result.then === "function") {
    return result;
  }
  return new Promise((resolve) => {
    chrome.storage.local.set(values, () => resolve());
  });
}

export async function getRules() {
  const result = await storageGet(RULES_KEY);
  return Array.isArray(result[RULES_KEY]) ? result[RULES_KEY] : [];
}

export async function saveRules(rules) {
  await storageSet({ [RULES_KEY]: rules });
  return rules;
}

export async function getSyncSources() {
  const result = await storageGet(SYNC_SOURCES_KEY);
  return Array.isArray(result[SYNC_SOURCES_KEY]) ? result[SYNC_SOURCES_KEY] : [];
}

export async function saveSyncSources(syncSources) {
  await storageSet({ [SYNC_SOURCES_KEY]: syncSources });
  return syncSources;
}

export function generateId() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function isValidRegex(pattern) {
  if (!pattern || typeof pattern !== "string") {
    return false;
  }
  try {
    new RegExp(pattern);
    return true;
  } catch (error) {
    return false;
  }
}
