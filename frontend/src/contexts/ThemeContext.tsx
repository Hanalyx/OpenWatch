import React, { createContext, useContext, useState, useEffect, useMemo } from 'react';
import { ThemeProvider, createTheme, PaletteMode } from '@mui/material';
import CssBaseline from '@mui/material/CssBaseline';

interface ThemeContextType {
  mode: PaletteMode;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType>({
  mode: 'light',
  toggleTheme: () => {},
});

export const useTheme = () => useContext(ThemeContext);

interface ThemeProviderProps {
  children: React.ReactNode;
}

export const CustomThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
  // Get initial theme from localStorage or system preference
  const getInitialMode = (): PaletteMode => {
    const savedMode = localStorage.getItem('themeMode');
    if (savedMode === 'light' || savedMode === 'dark') {
      return savedMode;
    }
    // Check system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }
    return 'light';
  };

  const [mode, setMode] = useState<PaletteMode>(getInitialMode);

  const toggleTheme = () => {
    const newMode = mode === 'light' ? 'dark' : 'light';
    setMode(newMode);
    localStorage.setItem('themeMode', newMode);
  };

  // Listen for system theme changes
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e: MediaQueryListEvent) => {
      if (!localStorage.getItem('themeMode')) {
        setMode(e.matches ? 'dark' : 'light');
      }
    };
    
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode,
          // Brand-aligned Material Design 3 color system
          primary: {
            main: mode === 'light' ? '#004aad' : '#90caf9', // Company blue primary
            light: mode === 'light' ? '#1976d2' : '#bbdefb', // M3-compliant light variant
            dark: mode === 'light' ? '#002f6c' : '#64b5f6', // M3-compliant dark variant
            contrastText: mode === 'light' ? '#FFFFFF' : '#002f6c',
          },
          secondary: {
            main: mode === 'light' ? '#FFC107' : '#FFD54F', // Logo yellow as secondary
            light: mode === 'light' ? '#FFD54F' : '#FFE082',
            dark: mode === 'light' ? '#FF8F00' : '#FFB300',
          },
          // Brand accent colors from logo
          success: {
            main: mode === 'light' ? '#4CAF50' : '#81C784', // M3 Success green
            light: mode === 'light' ? '#66BB6A' : '#A5D6A7',
            dark: mode === 'light' ? '#388E3C' : '#4CAF50',
          },
          warning: {
            main: mode === 'light' ? '#FF9800' : '#FFB74D', // M3 Warning orange
            light: mode === 'light' ? '#FFB74D' : '#FFCC02',
            dark: mode === 'light' ? '#F57C00' : '#FF9800',
          },
          error: {
            main: mode === 'light' ? '#B3261E' : '#F44336', // M3 Error red
            light: mode === 'light' ? '#E37373' : '#E57373',
            dark: mode === 'light' ? '#8C1D18' : '#D32F2F',
          },
          info: {
            main: mode === 'light' ? '#004aad' : '#90caf9', // Company blue as info
            light: mode === 'light' ? '#1976d2' : '#bbdefb',
            dark: mode === 'light' ? '#002f6c' : '#64b5f6',
          },
          // M3 Surface colors
          background: {
            default: mode === 'light' ? '#FEF7FF' : '#141218', // M3 Background
            paper: mode === 'light' ? '#FFFBFE' : '#1C1B1F', // M3 Surface
          },
          // M3 Text colors
          text: {
            primary: mode === 'light' ? '#1C1B1F' : '#E6E1E5',
            secondary: mode === 'light' ? '#49454F' : '#CAC4D0',
            disabled: mode === 'light' ? '#79747E' : '#938F99',
          },
        },
        // Material Design 3 typography
        typography: {
          fontFamily: 'Roboto, "Roboto Flex", "Google Sans", system-ui, sans-serif',
          fontSize: 14,
          h1: {
            fontWeight: 400,
            fontSize: '3.5rem', // M3 Display Large
            lineHeight: 1.12,
            letterSpacing: '-0.25px',
            marginBottom: '1rem',
          },
          h2: {
            fontWeight: 400,
            fontSize: '2.8125rem', // M3 Display Medium
            lineHeight: 1.16,
            letterSpacing: '0px',
            marginBottom: '0.75rem',
          },
          h3: {
            fontWeight: 400,
            fontSize: '2.25rem', // M3 Display Small
            lineHeight: 1.22,
            letterSpacing: '0px',
            marginBottom: '0.5rem',
          },
          h4: {
            fontWeight: 400,
            fontSize: '1.75rem', // M3 Headline Large
            lineHeight: 1.29,
            letterSpacing: '0px',
            marginBottom: '0.5rem',
          },
          h5: {
            fontWeight: 400,
            fontSize: '1.375rem', // M3 Headline Medium
            lineHeight: 1.27,
            letterSpacing: '0px',
            marginBottom: '0.5rem',
          },
          h6: {
            fontWeight: 400,
            fontSize: '1.125rem', // M3 Headline Small
            lineHeight: 1.33,
            letterSpacing: '0px',
            marginBottom: '0.5rem',
          },
          body1: {
            fontSize: '1rem', // M3 Body Large
            lineHeight: 1.5,
            letterSpacing: '0.03125em',
            marginBottom: '0.5rem',
          },
          body2: {
            fontSize: '0.875rem', // M3 Body Medium
            lineHeight: 1.43,
            letterSpacing: '0.015625em',
            marginBottom: '0.5rem',
          },
          caption: {
            fontSize: '0.75rem', // M3 Body Small
            lineHeight: 1.33,
            letterSpacing: '0.0333333em',
            color: mode === 'light' ? '#49454F' : '#CAC4D0',
          },
          button: {
            fontSize: '0.875rem', // M3 Label Large
            lineHeight: 1.25,
            letterSpacing: '0.1em',
            fontWeight: 500,
            textTransform: 'none', // M3 doesn't use all caps
          },
        },
        // M3 spacing scale (4dp grid system) with enhanced responsive scaling
        spacing: (factor: number) => `${4 * factor}px`,
        // Enhanced responsive breakpoints for comprehensive device support
        breakpoints: {
          keys: ['xs', 'sm', 'md', 'lg', 'xl'] as const,
          values: {
            xs: 0,       // Mobile portrait
            sm: 600,     // Mobile landscape / Small tablet
            md: 960,     // Tablet portrait
            lg: 1280,    // Desktop / Tablet landscape
            xl: 1920,    // Large desktop / TV
          },
          up: (key: any) => `@media (min-width:${key}px)`,
          down: (key: any) => `@media (max-width:${key - 0.05}px)`,
          between: (start: any, end: any) => `@media (min-width:${start}px) and (max-width:${end - 0.05}px)`,
          only: (key: any) => {
            const values = { xs: 0, sm: 600, md: 960, lg: 1280, xl: 1920 };
            const keys = ['xs', 'sm', 'md', 'lg', 'xl'];
            const keyIndex = keys.indexOf(key);
            const upperBound = keyIndex === keys.length - 1 ? 5000 : values[keys[keyIndex + 1] as keyof typeof values];
            return `@media (min-width:${values[key as keyof typeof values]}px) and (max-width:${upperBound - 0.05}px)`;
          },
        },
        // M3 shape system
        shape: {
          borderRadius: 16, // M3 uses larger border radius
        },
        // M3 elevation system
        shadows: [
          'none',
          mode === 'light' 
            ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
            : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
          mode === 'light'
            ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
            : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
          mode === 'light'
            ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
            : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
          mode === 'light'
            ? '0px 2px 4px 1px rgba(0, 0, 0, 0.2), 0px 4px 5px 0px rgba(0, 0, 0, 0.14)'
            : '0px 2px 4px 1px rgba(0, 0, 0, 0.2), 0px 4px 5px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 3px 5px 1px rgba(0, 0, 0, 0.2), 0px 6px 10px 0px rgba(0, 0, 0, 0.14)'
            : '0px 3px 5px 1px rgba(0, 0, 0, 0.2), 0px 6px 10px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 4px 5px 0px rgba(0, 0, 0, 0.12), 0px 1px 10px 0px rgba(0, 0, 0, 0.14)'
            : '0px 4px 5px 0px rgba(0, 0, 0, 0.12), 0px 1px 10px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 6px 10px 1px rgba(0, 0, 0, 0.12), 0px 1px 18px 0px rgba(0, 0, 0, 0.14)'
            : '0px 6px 10px 1px rgba(0, 0, 0, 0.12), 0px 1px 18px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 7px 10px 1px rgba(0, 0, 0, 0.12), 0px 2px 22px 0px rgba(0, 0, 0, 0.14)'
            : '0px 7px 10px 1px rgba(0, 0, 0, 0.12), 0px 2px 22px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 9px 11px 1px rgba(0, 0, 0, 0.12), 0px 3px 26px 0px rgba(0, 0, 0, 0.14)'
            : '0px 9px 11px 1px rgba(0, 0, 0, 0.12), 0px 3px 26px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 10px 13px 1px rgba(0, 0, 0, 0.12), 0px 4px 30px 0px rgba(0, 0, 0, 0.14)'
            : '0px 10px 13px 1px rgba(0, 0, 0, 0.12), 0px 4px 30px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 11px 15px 1px rgba(0, 0, 0, 0.12), 0px 5px 34px 0px rgba(0, 0, 0, 0.14)'
            : '0px 11px 15px 1px rgba(0, 0, 0, 0.12), 0px 5px 34px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 12px 17px 2px rgba(0, 0, 0, 0.12), 0px 6px 38px 0px rgba(0, 0, 0, 0.14)'
            : '0px 12px 17px 2px rgba(0, 0, 0, 0.12), 0px 6px 38px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 13px 19px 2px rgba(0, 0, 0, 0.12), 0px 7px 42px 0px rgba(0, 0, 0, 0.14)'
            : '0px 13px 19px 2px rgba(0, 0, 0, 0.12), 0px 7px 42px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 14px 21px 2px rgba(0, 0, 0, 0.12), 0px 8px 46px 0px rgba(0, 0, 0, 0.14)'
            : '0px 14px 21px 2px rgba(0, 0, 0, 0.12), 0px 8px 46px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 15px 23px 2px rgba(0, 0, 0, 0.12), 0px 9px 50px 0px rgba(0, 0, 0, 0.14)'
            : '0px 15px 23px 2px rgba(0, 0, 0, 0.12), 0px 9px 50px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 16px 25px 2px rgba(0, 0, 0, 0.12), 0px 10px 54px 0px rgba(0, 0, 0, 0.14)'
            : '0px 16px 25px 2px rgba(0, 0, 0, 0.12), 0px 10px 54px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 17px 27px 2px rgba(0, 0, 0, 0.12), 0px 11px 58px 0px rgba(0, 0, 0, 0.14)'
            : '0px 17px 27px 2px rgba(0, 0, 0, 0.12), 0px 11px 58px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 18px 29px 2px rgba(0, 0, 0, 0.12), 0px 12px 62px 0px rgba(0, 0, 0, 0.14)'
            : '0px 18px 29px 2px rgba(0, 0, 0, 0.12), 0px 12px 62px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 19px 31px 2px rgba(0, 0, 0, 0.12), 0px 13px 66px 0px rgba(0, 0, 0, 0.14)'
            : '0px 19px 31px 2px rgba(0, 0, 0, 0.12), 0px 13px 66px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 20px 33px 2px rgba(0, 0, 0, 0.12), 0px 14px 70px 0px rgba(0, 0, 0, 0.14)'
            : '0px 20px 33px 2px rgba(0, 0, 0, 0.12), 0px 14px 70px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 21px 35px 2px rgba(0, 0, 0, 0.12), 0px 15px 74px 0px rgba(0, 0, 0, 0.14)'
            : '0px 21px 35px 2px rgba(0, 0, 0, 0.12), 0px 15px 74px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 22px 37px 2px rgba(0, 0, 0, 0.12), 0px 16px 78px 0px rgba(0, 0, 0, 0.14)'
            : '0px 22px 37px 2px rgba(0, 0, 0, 0.12), 0px 16px 78px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 23px 39px 2px rgba(0, 0, 0, 0.12), 0px 17px 82px 0px rgba(0, 0, 0, 0.14)'
            : '0px 23px 39px 2px rgba(0, 0, 0, 0.12), 0px 17px 82px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 24px 41px 2px rgba(0, 0, 0, 0.12), 0px 18px 86px 0px rgba(0, 0, 0, 0.14)'
            : '0px 24px 41px 2px rgba(0, 0, 0, 0.12), 0px 18px 86px 0px rgba(0, 0, 0, 0.14)',
          mode === 'light'
            ? '0px 25px 43px 2px rgba(0, 0, 0, 0.12), 0px 19px 90px 0px rgba(0, 0, 0, 0.14)'
            : '0px 25px 43px 2px rgba(0, 0, 0, 0.12), 0px 19px 90px 0px rgba(0, 0, 0, 0.14)',
        ],
        // M3 component overrides
        components: {
          MuiButton: {
            styleOverrides: {
              root: {
                textTransform: 'none', // M3 doesn't use all caps
                fontWeight: 500,
                borderRadius: 20, // M3 uses larger border radius
                paddingLeft: 24,
                paddingRight: 24,
                paddingTop: 10,
                paddingBottom: 10,
                fontSize: '0.875rem',
                lineHeight: 1.25,
                letterSpacing: '0.1em',
                boxShadow: 'none',
                '&:hover': {
                  boxShadow: mode === 'light' 
                    ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
                    : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
                },
              },
              contained: {
                backgroundColor: mode === 'light' ? '#004aad' : '#90caf9', // Company blue
                color: mode === 'light' ? '#FFFFFF' : '#002f6c',
                '&:hover': {
                  backgroundColor: mode === 'light' ? '#002f6c' : '#64b5f6',
                  boxShadow: mode === 'light' 
                    ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
                    : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
                },
              },
              outlined: {
                borderColor: mode === 'light' ? '#004aad' : '#90caf9', // Company blue
                color: mode === 'light' ? '#004aad' : '#90caf9',
                '&:hover': {
                  borderColor: mode === 'light' ? '#002f6c' : '#64b5f6',
                  backgroundColor: mode === 'light' ? 'rgba(0, 74, 173, 0.08)' : 'rgba(144, 202, 249, 0.08)',
                },
              },
            },
          },
          MuiCard: {
            styleOverrides: {
              root: {
                borderRadius: 16, // M3 border radius
                border: 'none', // M3 doesn't use borders
                boxShadow: mode === 'light' 
                  ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
                  : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
                '&:hover': {
                  boxShadow: mode === 'light' 
                    ? '0px 2px 4px 1px rgba(0, 0, 0, 0.2), 0px 4px 5px 0px rgba(0, 0, 0, 0.14)'
                    : '0px 2px 4px 1px rgba(0, 0, 0, 0.2), 0px 4px 5px 0px rgba(0, 0, 0, 0.14)',
                },
              },
            },
          },
          MuiChip: {
            styleOverrides: {
              root: {
                borderRadius: 8, // M3 chip border radius
                fontSize: '0.75rem',
                fontWeight: 500,
                border: 'none',
                backgroundColor: mode === 'light' ? '#E7E0EC' : '#49454F',
                color: mode === 'light' ? '#1C1B1F' : '#E6E1E5',
              },
              filled: {
                border: 'none',
              },
              outlined: {
                border: mode === 'light' ? '1px solid #79747E' : '1px solid #938F99',
                backgroundColor: 'transparent',
              },
            },
          },
          MuiPaper: {
            styleOverrides: {
              root: {
                backgroundImage: 'none',
                borderRadius: 16, // M3 border radius
              },
              elevation1: {
                boxShadow: mode === 'light' 
                  ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
                  : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
              },
            },
          },
          MuiDrawer: {
            styleOverrides: {
              paper: {
                backgroundImage: 'none',
                borderRight: 'none', // M3 doesn't use borders
                backgroundColor: mode === 'light' ? '#FFFBFE' : '#1C1B1F',
                boxShadow: mode === 'light' 
                  ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
                  : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
                borderRadius: 0, // Remove border-radius for full-bleed left sidebar
              },
            },
          },
          MuiAppBar: {
            styleOverrides: {
              root: {
                backgroundImage: 'none',
                backgroundColor: mode === 'light' ? '#FFFBFE' : '#1C1B1F',
                color: mode === 'light' ? '#1C1B1F' : '#E6E1E5',
                boxShadow: mode === 'light'
                  ? '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)'
                  : '0px 1px 2px 0px rgba(0, 0, 0, 0.3), 0px 1px 3px 1px rgba(0, 0, 0, 0.15)',
                borderBottom: 'none', // M3 doesn't use borders
                borderRadius: 0, // Remove border-radius for full-bleed top bar
              },
            },
          },
          MuiListItemButton: {
            styleOverrides: {
              root: {
                borderRadius: 16, // M3 border radius
                margin: '4px 8px',
                '&.Mui-selected': {
                  backgroundColor: mode === 'light' 
                    ? 'rgba(103, 80, 164, 0.12)'
                    : 'rgba(208, 188, 255, 0.12)',
                  color: mode === 'light' ? '#6750A4' : '#D0BCFF',
                  '&:hover': {
                    backgroundColor: mode === 'light' 
                      ? 'rgba(103, 80, 164, 0.16)'
                      : 'rgba(208, 188, 255, 0.16)',
                  },
                },
                '&:hover': {
                  backgroundColor: mode === 'light'
                    ? 'rgba(28, 27, 31, 0.08)'
                    : 'rgba(230, 225, 229, 0.08)',
                },
              },
            },
          },
          MuiTableCell: {
            styleOverrides: {
              root: {
                borderBottom: mode === 'light' 
                  ? '1px solid #E7E0EC' 
                  : '1px solid #49454F',
              },
              head: {
                backgroundColor: mode === 'light' ? '#F3EDF7' : '#141218',
                fontWeight: 500,
                fontSize: '0.75rem',
              },
            },
          },
          MuiContainer: {
            styleOverrides: {
              root: {
                paddingTop: 24,
                paddingBottom: 24,
                // Enhanced responsive padding
                '@media (max-width: 600px)': {
                  paddingLeft: 16,
                  paddingRight: 16,
                  paddingTop: 16,
                  paddingBottom: 16,
                },
                '@media (min-width: 1920px)': {
                  paddingTop: 32,
                  paddingBottom: 32,
                },
              },
            },
          },
          MuiGrid: {
            styleOverrides: {
              root: {
                '&.MuiGrid-container': {
                  marginTop: 0,
                },
              },
            },
          },
          MuiSkeleton: {
            styleOverrides: {
              root: {
                borderRadius: 16, // M3 border radius
              },
            },
          },
          // Enhanced accessibility and focus management
          MuiFocusVisible: {
            styleOverrides: {
              root: {
                outline: `2px solid ${mode === 'light' ? '#004aad' : '#90caf9'}`,
                outlineOffset: '2px',
                borderRadius: 4,
              },
            },
          },
          MuiTooltip: {
            styleOverrides: {
              tooltip: {
                backgroundColor: mode === 'light' ? '#49454F' : '#E6E1E5',
                color: mode === 'light' ? '#FFFFFF' : '#1C1B1F',
                fontSize: '0.75rem',
                borderRadius: 8,
                padding: '8px 12px',
                maxWidth: 300,
                wordWrap: 'break-word',
              },
              arrow: {
                color: mode === 'light' ? '#49454F' : '#E6E1E5',
              },
            },
          },
          // Improved form controls for accessibility
          MuiTextField: {
            styleOverrides: {
              root: {
                '& .MuiInputLabel-root': {
                  fontSize: '1rem',
                  fontWeight: 400,
                },
                '& .MuiOutlinedInput-root': {
                  borderRadius: 8,
                  '& fieldset': {
                    borderColor: mode === 'light' ? '#79747E' : '#938F99',
                  },
                  '&:hover fieldset': {
                    borderColor: mode === 'light' ? '#004aad' : '#90caf9',
                  },
                  '&.Mui-focused fieldset': {
                    borderColor: mode === 'light' ? '#004aad' : '#90caf9',
                    borderWidth: 2,
                  },
                  '&.Mui-error fieldset': {
                    borderColor: mode === 'light' ? '#B3261E' : '#F44336',
                  },
                },
                '& .MuiFormHelperText-root': {
                  fontSize: '0.75rem',
                  marginLeft: 0,
                  marginTop: 4,
                },
              },
            },
          },
        },
      }),
    [mode]
  );

  return (
    <ThemeContext.Provider value={{ mode, toggleTheme }}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </ThemeContext.Provider>
  );
};

export default CustomThemeProvider;