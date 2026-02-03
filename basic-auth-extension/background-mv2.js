const STATUS = {
  IDLE: "idle",
  OK: "ok",
  AUTH_FAILED: "auth_failed",
  CONFLICT: "conflict"
};

const BADGE_CONFIG = {
  ok: { text: " ", color: "#4CAF50" },
  auth_failed: { text: " ", color: "#F44336" },
  conflict: { text: " ", color: "#FFC107" },
  idle: { text: "", color: "#9E9E9E" }
};

const actionApi = chrome.action || chrome.browserAction;
const tabStatus = new Map();
const requestMeta = new Map();
let rulesCache = [];

function setBadge(tabId, state) {
  if (!actionApi || tabId < 0) {
    return;
  }
  const config = BADGE_CONFIG[state] || BADGE_CONFIG.idle;
  actionApi.setBadgeText({ tabId, text: config.text });
  actionApi.setBadgeBackgroundColor({ tabId, color: config.color });
}

function notifyTabStatus(tabId) {
  const current = tabStatus.get(tabId);
  const state = current ? current.state : STATUS.IDLE;
  const ruleId = current ? current.ruleId : null;
  const matchRuleIds = current ? current.matchRuleIds || [] : [];
  chrome.runtime.sendMessage({ type: "tabStatusChanged", tabId, status: state, ruleId, matchRuleIds });
}

function setTabStatus(tabId, state, ruleId, url, matchRuleIds) {
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
    matchRuleIds: matchRuleIds || [],
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

function updateTabStatusForUrl(tabId, url) {
  if (tabId < 0) {
    return;
  }
  if (!url || !url.startsWith("http")) {
    setTabStatus(tabId, STATUS.IDLE, null, url || "", []);
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
      selected ? selected.id : null,
      url,
      matches.map((rule) => rule.id).filter(Boolean)
    );
    return;
  }
  const selected = matches[0];
  if (shouldKeepAuthFailed(tabId, selected ? selected.id : null)) {
    setTabStatus(
      tabId,
      STATUS.AUTH_FAILED,
      selected ? selected.id : null,
      url,
      [selected ? selected.id : null].filter(Boolean)
    );
    return;
  }
  setTabStatus(tabId, STATUS.OK, selected ? selected.id : null, url, [selected ? selected.id : null].filter(Boolean));
}

function handleAuth(details) {
  const tabId = details.tabId;
  const url = details.url || "";
  if (tabId < 0 || details.isProxy) {
    return {};
  }
  if (details.scheme && details.scheme.toLowerCase() !== "basic") {
    return {};
  }

  const matches = matchRules(rulesCache, url);
  if (matches.length === 0) {
    setTabStatus(tabId, STATUS.IDLE, null, url, []);
    return {};
  }

  const selected = selectRule(matches);
  const hasConflict = matches.length > 1;
  const requestId = details.requestId;
  const existing = requestMeta.get(requestId);

  if (existing) {
    existing.attempts += 1;
    if (!existing.conflict) {
      setTabStatus(tabId, STATUS.AUTH_FAILED, selected ? selected.id : null, url, [selected ? selected.id : null].filter(Boolean));
    }
    return { cancel: true };
  }

  requestMeta.set(requestId, {
    tabId,
    ruleId: selected ? selected.id : null,
    attempts: 0,
    conflict: hasConflict
  });

  if (hasConflict) {
    setTabStatus(
      tabId,
      STATUS.CONFLICT,
      selected ? selected.id : null,
      url,
      matches.map((rule) => rule.id).filter(Boolean)
    );
  } else {
    if (shouldKeepAuthFailed(tabId, selected ? selected.id : null)) {
      setTabStatus(
        tabId,
        STATUS.AUTH_FAILED,
        selected ? selected.id : null,
        url,
        [selected ? selected.id : null].filter(Boolean)
      );
    } else {
      setTabStatus(tabId, STATUS.OK, selected ? selected.id : null, url, [selected ? selected.id : null].filter(Boolean));
    }
  }

  return {
    authCredentials: {
      username: selected && selected.username ? selected.username : "",
      password: selected && selected.password ? selected.password : ""
    }
  };
}

chrome.webRequest.onAuthRequired.addListener(
  (details) => handleAuth(details),
  { urls: ["<all_urls>"] },
  ["blocking"]
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    const meta = requestMeta.get(details.requestId);
    if (!meta) {
      return;
    }
    if (!meta.conflict) {
      if (details.statusCode === 401) {
        setTabStatus(meta.tabId, STATUS.AUTH_FAILED, meta.ruleId, details.url, [meta.ruleId].filter(Boolean));
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
      setTabStatus(meta.tabId, STATUS.AUTH_FAILED, meta.ruleId, details.url, [meta.ruleId].filter(Boolean));
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
    const status = tabStatus.get(message.tabId) || { state: STATUS.IDLE };
    sendResponse({
      status: status.state,
      ruleId: status.ruleId || null,
      matchRuleIds: status.matchRuleIds || []
    });
    return true;
  }
  if (message.type === "refreshTabStatus") {
    updateTabStatusForUrl(message.tabId, message.url);
    return false;
  }
  return false;
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (tab && tab.url) {
      updateTabStatusForUrl(tabId, tab.url);
    }
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    updateTabStatusForUrl(tabId, changeInfo.url);
    return;
  }
  if (changeInfo.status === "complete" && tab && tab.url) {
    updateTabStatusForUrl(tabId, tab.url);
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

function refreshAllTabs() {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab && tab.id != null && tab.url) {
        updateTabStatusForUrl(tab.id, tab.url);
      }
    }
  });
}

function setRulesCache(rules) {
  rulesCache = Array.isArray(rules) ? rules : [];
}

function loadRules() {
  chrome.storage.local.get("rules", (result) => {
    setRulesCache(result && result.rules ? result.rules : []);
    refreshAllTabs();
  });
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local" || !changes.rules) {
    return;
  }
  setRulesCache(changes.rules.newValue || []);
  refreshAllTabs();
});

chrome.runtime.onInstalled.addListener(() => {
  loadRules();
});

chrome.runtime.onStartup.addListener(() => {
  loadRules();
});

loadRules();
