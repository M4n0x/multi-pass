import { STATUS, BADGE_CONFIG } from "./shared/constants.js";
import { getRules } from "./shared/storage.js";

const tabStatus = new Map();
const requestMeta = new Map();

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

async function updateTabStatusForUrl(tabId, url) {
  if (tabId < 0) {
    return;
  }
  if (!url || !url.startsWith("http")) {
    setTabStatus(tabId, STATUS.IDLE, null, url || "");
    return;
  }
  const rules = await getRules();
  const matches = matchRules(rules, url);
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
  const tabId = details.tabId;
  const url = details.url || "";
  if (tabId < 0 || details.isProxy) {
    return {};
  }
  if (details.scheme && details.scheme.toLowerCase() !== "basic") {
    return {};
  }

  const rules = await getRules();
  const matches = matchRules(rules, url);
  if (matches.length === 0) {
    setTabStatus(tabId, STATUS.IDLE, null, url, []);
    return {};
  }

  const selected = selectRule(matches);
  const hasConflict = matches.length > 1;

  // If auth already failed for this tab/rule, let browser show native prompt
  if (shouldKeepAuthFailed(tabId, selected?.id)) {
    return {};
  }

  const requestId = details.requestId;
  const existing = requestMeta.get(requestId);

  if (existing) {
    existing.attempts += 1;
    if (!existing.conflict) {
      setTabStatus(tabId, STATUS.AUTH_FAILED, selected?.id || null, url, [selected?.id].filter(Boolean));
    }
    // Auth failed, let browser show native prompt
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
  if (message.type === "clearAuthFailed") {
    const ruleId = message.ruleId;
    for (const [tabId, status] of tabStatus.entries()) {
      if (status.state === STATUS.AUTH_FAILED && status.ruleId === ruleId) {
        tabStatus.delete(tabId);
      }
    }
    return false;
  }
  return false;
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (tab?.url) {
    updateTabStatusForUrl(tabId, tab.url);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    updateTabStatusForUrl(tabId, changeInfo.url);
    return;
  }
  if (changeInfo.status === "complete" && tab?.url) {
    updateTabStatusForUrl(tabId, tab.url);
    // Re-apply badge after page load completes (Chrome can clear it)
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
  if (areaName !== "local" || !changes.rules) {
    return;
  }
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.id != null && tab.url) {
        updateTabStatusForUrl(tab.id, tab.url);
      }
    }
  });
});

async function refreshAllTabs() {
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (tab.id != null && tab.url) {
      updateTabStatusForUrl(tab.id, tab.url);
    }
  }
}

chrome.runtime.onInstalled.addListener(() => {
  refreshAllTabs();
});

chrome.runtime.onStartup.addListener(() => {
  refreshAllTabs();
});
