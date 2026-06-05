import { extendTheme } from '@mui/material/styles';
import {
  darkTokens,
  lightTokens,
  structural,
  type ModeColorTokens,
} from './tokens';

// MUI v7 theme — CSS-variables mode.
//
// cssVarPrefix: 'ow' emits all theme tokens as --ow-* variables so the
// design-token contract from app/docs/frontend_design_tokens.md is
// realized at runtime.
//
// Spec: frontend-foundation AC-06, AC-16.

// MUI's augmentColor (used internally by createPalette) requires
// hex / rgb / hsl / color() — it CANNOT parse oklch(). Per-mode
// hex equivalents live alongside the oklch in tokens; we pass the
// hex form here and reserve the oklch values for direct CSS use
// (via the --ow-* variables in globals.css).
function paletteForMode(t: ModeColorTokens) {
  return {
    background: {
      default: t.bg0,
      paper: t.bg1,
    },
    text: {
      primary: t.fg0,
      secondary: t.fg1,
      disabled: t.fg3,
    },
    primary: {
      main: t.infoHex,
      contrastText: t.infoOn,
    },
    error: {
      main: t.critHex,
      contrastText: t.critOn,
    },
    warning: {
      main: t.warnHex,
      contrastText: t.warnOn,
    },
    success: {
      main: t.okHex,
      contrastText: t.okOn,
    },
    info: {
      main: t.infoHex,
      contrastText: t.infoOn,
    },
    divider: t.line,
  };
}

export const theme = extendTheme({
  cssVarPrefix: 'ow',
  colorSchemeSelector: 'data',
  defaultColorScheme: 'dark',
  colorSchemes: {
    dark: {
      palette: paletteForMode(darkTokens),
    },
    light: {
      palette: paletteForMode(lightTokens),
    },
  },
  shape: {
    borderRadius: 8,
  },
  typography: {
    fontFamily: structural.fontSans,
    fontSize: 14,
  },
});

export default theme;
