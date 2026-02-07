const RULES_KEY = "rules";
const SYNC_SOURCES_KEY = "syncSources";

function storageGet(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get(key, (items) => resolve(items || {}));
  });
}

function storageSet(values) {
  return new Promise((resolve) => {
    chrome.storage.local.set(values, () => resolve());
  });
}

function sendRuntimeMessage(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(response || null);
      });
    } catch (error) {
      resolve(null);
    }
  });
}

function createLockedError() {
  const error = new Error("Vault is locked");
  error.code = "VAULT_LOCKED";
  return error;
}

export function isVaultLockedError(error) {
  return Boolean(error && error.code === "VAULT_LOCKED");
}

export async function getVaultState() {
  const response = await sendRuntimeMessage({ type: "getVaultState" });
  if (!response || response.supported !== true) {
    return {
      supported: false,
      enabled: false,
      unlocked: true
    };
  }
  return {
    supported: true,
    enabled: Boolean(response.enabled),
    unlocked: Boolean(response.unlocked)
  };
}

export async function unlockVault(password) {
  return (
    (await sendRuntimeMessage({ type: "unlockVault", password })) || {
      ok: false,
      error: "unavailable"
    }
  );
}

export async function lockVault() {
  return (
    (await sendRuntimeMessage({ type: "lockVault" })) || {
      ok: false,
      error: "unavailable"
    }
  );
}

export async function enableVault(password) {
  return (
    (await sendRuntimeMessage({ type: "enableVault", password })) || {
      ok: false,
      error: "unavailable"
    }
  );
}

export async function disableVault() {
  return (
    (await sendRuntimeMessage({ type: "disableVault" })) || {
      ok: false,
      error: "unavailable"
    }
  );
}

export async function changeVaultPassword(currentPassword, nextPassword) {
  return (
    (await sendRuntimeMessage({
      type: "changeVaultPassword",
      currentPassword,
      nextPassword
    })) || {
      ok: false,
      error: "unavailable"
    }
  );
}

async function getRulesFromVault() {
  const response = await sendRuntimeMessage({ type: "vaultGetRules" });
  if (!response) {
    throw new Error("Unable to reach vault service");
  }
  if (response.locked) {
    throw createLockedError();
  }
  if (!Array.isArray(response.rules)) {
    return [];
  }
  return response.rules;
}

async function saveRulesToVault(rules) {
  const response = await sendRuntimeMessage({ type: "vaultSaveRules", rules });
  if (!response) {
    throw new Error("Unable to reach vault service");
  }
  if (response.locked) {
    throw createLockedError();
  }
  if (!response.ok) {
    throw new Error(response.error || "Failed to save vault rules");
  }
  return Array.isArray(response.rules) ? response.rules : rules;
}

export async function getRules() {
  const vault = await getVaultState();
  if (vault.supported && vault.enabled) {
    return getRulesFromVault();
  }
  const result = await storageGet(RULES_KEY);
  return Array.isArray(result[RULES_KEY]) ? result[RULES_KEY] : [];
}

export async function saveRules(rules) {
  const vault = await getVaultState();
  if (vault.supported && vault.enabled) {
    return saveRulesToVault(rules);
  }
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
