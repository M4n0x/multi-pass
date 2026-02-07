function createWebAuthnError(code, message) {
  const error = new Error(message || code);
  error.code = code;
  return error;
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

function normalizeBufferSource(value) {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return null;
}

function mapDomException(error) {
  switch (error?.name) {
    case "NotAllowedError":
      return "webauthn-cancelled";
    case "InvalidStateError":
      return "webauthn-already-registered";
    case "NotSupportedError":
      return "webauthn-unavailable";
    case "SecurityError":
      return "webauthn-security-error";
    case "AbortError":
      return "webauthn-cancelled";
    default:
      return "webauthn-failed";
  }
}

function toPublicKeyCredentialDescriptor(descriptor) {
  if (!descriptor || typeof descriptor !== "object" || typeof descriptor.id !== "string") {
    return null;
  }
  return {
    type: "public-key",
    id: base64ToBytes(descriptor.id),
    transports: Array.isArray(descriptor.transports) ? descriptor.transports : undefined
  };
}

function getPrfResult(extensionResults) {
  const value = extensionResults?.prf?.results?.first;
  const bytes = normalizeBufferSource(value);
  if (!bytes || bytes.length < 16) {
    return null;
  }
  return bytes;
}

function ensureWebAuthnRuntime() {
  if (
    typeof window === "undefined" ||
    !window.isSecureContext ||
    typeof PublicKeyCredential === "undefined" ||
    !navigator?.credentials
  ) {
    throw createWebAuthnError("webauthn-unavailable", "WebAuthn is unavailable.");
  }
}

export async function detectWebAuthnSupport() {
  if (
    typeof window === "undefined" ||
    !window.isSecureContext ||
    typeof PublicKeyCredential === "undefined" ||
    !navigator?.credentials
  ) {
    return {
      supported: false,
      platformAuthenticator: false,
      reason: "This browser does not expose WebAuthn in extension pages."
    };
  }

  let platformAuthenticator = false;
  if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
    try {
      platformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (error) {
      platformAuthenticator = false;
    }
  }

  return {
    supported: true,
    platformAuthenticator
  };
}

export async function runWebAuthnSetup(options) {
  ensureWebAuthnRuntime();

  try {
    const challenge = base64ToBytes(options.challenge);
    const userId = base64ToBytes(options.userId);
    const prfSalt = base64ToBytes(options.prfSalt);

    const publicKey = {
      challenge,
      rp: {
        name: options.rpName || "Multi-pass Vault"
      },
      user: {
        id: userId,
        name: options.userName || "multi-pass-user",
        displayName: options.userDisplayName || "Multi-pass Vault"
      },
      timeout: typeof options.timeout === "number" ? options.timeout : 90_000,
      attestation: "none",
      pubKeyCredParams: Array.isArray(options.pubKeyCredParams)
        ? options.pubKeyCredParams
        : [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 }
          ],
      authenticatorSelection: {
        authenticatorAttachment: options.authenticatorAttachment || "platform",
        userVerification: options.userVerification || "required",
        residentKey: options.residentKey || "preferred"
      },
      extensions: {
        prf: {
          eval: {
            first: prfSalt
          }
        }
      }
    };

    if (Array.isArray(options.excludeCredentials) && options.excludeCredentials.length) {
      publicKey.excludeCredentials = options.excludeCredentials
        .map(toPublicKeyCredentialDescriptor)
        .filter(Boolean);
    }

    const credential = await navigator.credentials.create({ publicKey });
    if (!credential || credential.type !== "public-key") {
      throw createWebAuthnError("webauthn-failed", "Credential registration failed.");
    }

    const extensionResults =
      typeof credential.getClientExtensionResults === "function"
        ? credential.getClientExtensionResults()
        : {};
    const prfResult = getPrfResult(extensionResults);
    if (!prfResult) {
      throw createWebAuthnError(
        "webauthn-prf-unavailable",
        "This authenticator does not support PRF-based unlock."
      );
    }

    const response = credential.response;
    return {
      credentialId: bytesToBase64(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        clientDataJSON: bytesToBase64(new Uint8Array(response.clientDataJSON)),
        attestationObject: bytesToBase64(new Uint8Array(response.attestationObject))
      },
      transports:
        typeof response.getTransports === "function" ? response.getTransports() : undefined,
      prfOutput: bytesToBase64(prfResult)
    };
  } catch (error) {
    if (error?.code) {
      throw error;
    }
    throw createWebAuthnError(mapDomException(error), error?.message || "WebAuthn setup failed.");
  }
}

export async function runWebAuthnUnlock(options) {
  ensureWebAuthnRuntime();

  try {
    const challenge = base64ToBytes(options.challenge);
    const prfSalt = base64ToBytes(options.prfSalt);

    const allowCredentials = Array.isArray(options.allowCredentials)
      ? options.allowCredentials.map(toPublicKeyCredentialDescriptor).filter(Boolean)
      : [];

    const publicKey = {
      challenge,
      timeout: typeof options.timeout === "number" ? options.timeout : 60_000,
      userVerification: options.userVerification || "required",
      allowCredentials,
      extensions: {
        prf: {
          eval: {
            first: prfSalt
          }
        }
      }
    };

    const credential = await navigator.credentials.get({ publicKey });
    if (!credential || credential.type !== "public-key") {
      throw createWebAuthnError("webauthn-failed", "Credential assertion failed.");
    }

    const extensionResults =
      typeof credential.getClientExtensionResults === "function"
        ? credential.getClientExtensionResults()
        : {};
    const prfResult = getPrfResult(extensionResults);
    if (!prfResult) {
      throw createWebAuthnError(
        "webauthn-prf-unavailable",
        "This authenticator does not support PRF-based unlock."
      );
    }

    const response = credential.response;

    return {
      credentialId: bytesToBase64(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        clientDataJSON: bytesToBase64(new Uint8Array(response.clientDataJSON)),
        authenticatorData: bytesToBase64(new Uint8Array(response.authenticatorData)),
        signature: bytesToBase64(new Uint8Array(response.signature)),
        userHandle: response.userHandle
          ? bytesToBase64(new Uint8Array(response.userHandle))
          : null
      },
      prfOutput: bytesToBase64(prfResult)
    };
  } catch (error) {
    if (error?.code) {
      throw error;
    }
    throw createWebAuthnError(mapDomException(error), error?.message || "WebAuthn unlock failed.");
  }
}
