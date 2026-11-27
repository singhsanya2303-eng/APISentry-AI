import { useCallback, useEffect, useMemo, useState } from "react";
import {
  normalizeTheme,
  THEME_STORAGE_KEY,
  ThemeContext,
} from "./themeContext";

function readStoredTheme() {
  try {
    return normalizeTheme(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return null;
  }
}

function getInitialTheme() {
  // A saved, valid preference wins. The pre-hydration script has already
  // applied it to <html>, so reading that value keeps React in sync.
  const stored = readStoredTheme();
  if (stored) return stored;

  const applied = normalizeTheme(document.documentElement.getAttribute("data-theme"));
  if (applied) return applied;

  // System preference is consulted only when no valid saved preference exists.
  if (typeof window.matchMedia === "function") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return "light";
}

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(getInitialTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  // Persist only when the user explicitly chooses a theme. With no saved
  // preference, the system choice remains the initial value on every visit.
  const setTheme = useCallback((nextTheme) => {
    const resolved = normalizeTheme(nextTheme);
    if (!resolved) return;
    setThemeState(resolved);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, resolved);
    } catch {
      // Storage can be unavailable (private browsing); the theme still applies.
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(theme === "dark" ? "light" : "dark");
  }, [setTheme, theme]);

  const value = useMemo(
    () => ({ theme, setTheme, toggleTheme, storageKey: THEME_STORAGE_KEY }),
    [theme, setTheme, toggleTheme]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}
