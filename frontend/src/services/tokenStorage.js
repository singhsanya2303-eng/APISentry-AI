const ACCESS_TOKEN_KEY = "apisentry.access_token";

export const UNAUTHORIZED_EVENT = "apisentry:unauthorized";

export function getAccessToken() {
  try {
    return window.localStorage.getItem(ACCESS_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setAccessToken(token) {
  if (!token) return;
  try {
    window.localStorage.setItem(ACCESS_TOKEN_KEY, token);
  } catch {
    // Storage can be unavailable (private mode); in-memory state still works.
  }
}

export function clearAccessToken() {
  try {
    window.localStorage.removeItem(ACCESS_TOKEN_KEY);
  } catch {
    // Nothing to clear when storage is unavailable.
  }
}
