export const STATUS = {
  IDLE: "idle",
  OK: "ok",
  AUTH_FAILED: "auth_failed",
  CONFLICT: "conflict"
};

export const BADGE_CONFIG = {
  ok: { text: " ", color: "#4CAF50" },
  auth_failed: { text: " ", color: "#F44336" },
  conflict: { text: " ", color: "#FFC107" },
  idle: { text: "", color: "#9E9E9E" }
};

export const STATUS_LABELS = {
  idle: "Idle",
  ok: "Active",
  auth_failed: "Auth failed",
  conflict: "Conflict"
};
