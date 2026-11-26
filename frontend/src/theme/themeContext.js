import { createContext, useContext } from "react";

export const THEME_STORAGE_KEY = "apisentry.theme";
const SUPPORTED_THEMES = ["light", "dark"];

export function normalizeTheme(value) {
  return SUPPORTED_THEMES.includes(value) ? value : null;
}

export const ThemeContext = createContext(null);

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme must be used inside ThemeProvider");
  return context;
}
