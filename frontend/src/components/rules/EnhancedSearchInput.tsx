import React, { useState, useCallback, useMemo } from 'react';
import {
  Autocomplete,
  TextField,
  Box,
  Chip,
  Paper,
  Typography,
  InputAdornment,
  CircularProgress,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Search as SearchIcon,
  Clear as ClearIcon,
  History as HistoryIcon,
  Bookmark as BookmarkIcon,
  Tag as TagIcon,
} from '@mui/icons-material';
import { useDebounce } from '../../hooks/useDebounce';

export interface SearchSuggestion {
  type: 'rule' | 'tag' | 'category' | 'framework' | 'history' | 'saved';
  value: string;
  label: string;
  description?: string;
  count?: number;
  icon?: React.ReactNode;
}

interface EnhancedSearchInputProps {
  value: string;
  onChange: (value: string) => void;
  onSuggestionSelect?: (suggestion: SearchSuggestion) => void;
  placeholder?: string;
  disabled?: boolean;
  showHistory?: boolean;
  showSavedSearches?: boolean;
}

const EnhancedSearchInput: React.FC<EnhancedSearchInputProps> = ({
  value,
  onChange,
  onSuggestionSelect,
  placeholder = 'Search rules, tags, or categories...',
  disabled = false,
  showHistory = true,
  showSavedSearches = true,
}) => {
  const theme = useTheme();
  const [inputValue, setInputValue] = useState(value);
  const [suggestions, setSuggestions] = useState<SearchSuggestion[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [open, setOpen] = useState(false);

  const debouncedInputValue = useDebounce(inputValue, 200);

  // Search history (would be stored in localStorage in real implementation)
  const searchHistory = useMemo(
    () => [
      {
        type: 'history' as const,
        value: 'ssh authentication',
        label: 'ssh authentication',
        icon: <HistoryIcon fontSize="small" />,
      },
      {
        type: 'history' as const,
        value: 'firewall security',
        label: 'firewall security',
        icon: <HistoryIcon fontSize="small" />,
      },
      {
        type: 'history' as const,
        value: 'password complexity',
        label: 'password complexity',
        icon: <HistoryIcon fontSize="small" />,
      },
    ],
    []
  );

  // Saved searches (would be stored in user preferences)
  const savedSearches = useMemo(
    () => [
      {
        type: 'saved' as const,
        value: 'severity:high AND category:authentication',
        label: 'High Priority Auth Rules',
        description: 'Critical authentication security rules',
        icon: <BookmarkIcon fontSize="small" />,
      },
      {
        type: 'saved' as const,
        value: 'framework:nist AND platform:rhel',
        label: 'NIST RHEL Rules',
        description: 'NIST framework rules for RHEL systems',
        icon: <BookmarkIcon fontSize="small" />,
      },
    ],
    []
  );

  // Generate suggestions based on input
  const generateSuggestions = useCallback(
    async (query: string): Promise<SearchSuggestion[]> => {
      if (!query.trim()) {
        // Return recent history and saved searches when no query
        const suggestions: SearchSuggestion[] = [];

        if (showSavedSearches) {
          suggestions.push(...savedSearches);
        }

        if (showHistory && suggestions.length < 5) {
          suggestions.push(...searchHistory.slice(0, 5 - suggestions.length));
        }

        return suggestions;
      }

      const suggestions: SearchSuggestion[] = [];
      const lowerQuery = query.toLowerCase();

      try {
        // Mock API call for auto-complete suggestions
        // In real implementation, this would call a dedicated autocomplete endpoint
        const mockSuggestions: SearchSuggestion[] = [
          {
            type: 'rule',
            value: 'SSH Root Login',
            label: 'SSH Root Login',
            description: 'Disable SSH root login access',
            count: 1,
          },
          {
            type: 'tag',
            value: 'authentication',
            label: 'authentication',
            description: '12 rules',
            icon: <TagIcon fontSize="small" />,
            count: 12,
          },
          {
            type: 'category',
            value: 'network_security',
            label: 'Network Security',
            description: '8 rules',
            count: 8,
          },
          {
            type: 'framework',
            value: 'nist',
            label: 'NIST 800-53',
            description: '45 controls',
            count: 45,
          },
        ];

        // Filter suggestions based on query
        const filtered = mockSuggestions.filter(
          (s) =>
            s.label.toLowerCase().includes(lowerQuery) ||
            s.value.toLowerCase().includes(lowerQuery) ||
            (s.description && s.description.toLowerCase().includes(lowerQuery))
        );

        suggestions.push(...filtered);

        // Add matching search history
        if (showHistory) {
          const matchingHistory = searchHistory.filter((h) =>
            h.label.toLowerCase().includes(lowerQuery)
          );
          suggestions.push(...matchingHistory);
        }

        // Add matching saved searches
        if (showSavedSearches) {
          const matchingSaved = savedSearches.filter(
            (s) =>
              s.label.toLowerCase().includes(lowerQuery) ||
              s.description?.toLowerCase().includes(lowerQuery)
          );
          suggestions.push(...matchingSaved);
        }
      } catch (error) {
        console.error('Error generating search suggestions:', error);
      }

      return suggestions.slice(0, 10); // Limit to 10 suggestions
    },
    [searchHistory, savedSearches, showHistory, showSavedSearches]
  );

  // Update suggestions when debounced input changes
  React.useEffect(() => {
    if (open) {
      setIsLoading(true);
      generateSuggestions(debouncedInputValue).then((newSuggestions) => {
        setSuggestions(newSuggestions);
        setIsLoading(false);
      });
    }
  }, [debouncedInputValue, open, generateSuggestions]);

  const handleInputChange = (event: React.SyntheticEvent, newInputValue: string) => {
    setInputValue(newInputValue);
  };

  const handleChange = (
    event: React.SyntheticEvent,
    newValue: SearchSuggestion | string | null
  ) => {
    if (typeof newValue === 'string') {
      onChange(newValue);
      setInputValue(newValue);
    } else if (newValue) {
      onChange(newValue.value);
      setInputValue(newValue.value);
      if (onSuggestionSelect) {
        onSuggestionSelect(newValue);
      }
    }
  };

  const getOptionLabel = (option: SearchSuggestion | string) => {
    if (typeof option === 'string') {
      return option;
    }
    return option.label;
  };

  // Custom render function for Autocomplete dropdown options
  const renderOption = (props: React.HTMLAttributes<HTMLLIElement>, option: SearchSuggestion) => {
    const getTypeColor = (type: string) => {
      switch (type) {
        case 'rule':
          return theme.palette.primary.main;
        case 'tag':
          return theme.palette.secondary.main;
        case 'category':
          return theme.palette.info.main;
        case 'framework':
          return theme.palette.success.main;
        case 'history':
          return theme.palette.text.secondary;
        case 'saved':
          return theme.palette.warning.main;
        default:
          return theme.palette.text.secondary;
      }
    };

    return (
      <Box component="li" {...props} sx={{ p: 1 }}>
        <Box display="flex" alignItems="center" width="100%">
          <Box
            sx={{
              mr: 1.5,
              color: getTypeColor(option.type),
              display: 'flex',
              alignItems: 'center',
            }}
          >
            {option.icon || <SearchIcon fontSize="small" />}
          </Box>
          <Box flex={1}>
            <Typography variant="body2" fontWeight="medium">
              {option.label}
            </Typography>
            {option.description && (
              <Typography variant="caption" color="text.secondary">
                {option.description}
              </Typography>
            )}
          </Box>
          {option.count && (
            <Chip
              label={option.count}
              size="small"
              sx={{
                backgroundColor: alpha(getTypeColor(option.type), 0.1),
                color: getTypeColor(option.type),
                fontSize: '0.7rem',
                height: 20,
              }}
            />
          )}
          <Chip
            label={option.type}
            size="small"
            variant="outlined"
            sx={{
              ml: 1,
              fontSize: '0.7rem',
              height: 20,
              textTransform: 'capitalize',
            }}
          />
        </Box>
      </Box>
    );
  };

  return (
    <Autocomplete
      freeSolo
      open={open}
      onOpen={() => setOpen(true)}
      onClose={() => setOpen(false)}
      inputValue={inputValue}
      onInputChange={handleInputChange}
      onChange={handleChange}
      options={suggestions}
      getOptionLabel={getOptionLabel}
      renderOption={renderOption}
      loading={isLoading}
      disabled={disabled}
      filterOptions={(options) => options} // We handle filtering ourselves
      PaperComponent={({ children, ...props }) => (
        <Paper {...props} elevation={8} sx={{ mt: 1 }}>
          {children}
        </Paper>
      )}
      renderInput={(params) => (
        <TextField
          {...params}
          placeholder={placeholder}
          variant="outlined"
          size="small"
          InputProps={{
            ...params.InputProps,
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
            endAdornment: (
              <InputAdornment position="end">
                {isLoading && <CircularProgress size={16} />}
                {inputValue && !isLoading && (
                  <ClearIcon
                    fontSize="small"
                    sx={{
                      cursor: 'pointer',
                      color: 'action.active',
                      '&:hover': { color: 'text.primary' },
                    }}
                    onClick={() => {
                      setInputValue('');
                      onChange('');
                    }}
                  />
                )}
              </InputAdornment>
            ),
          }}
        />
      )}
      sx={{
        flex: 1,
        maxWidth: 500,
        '& .MuiOutlinedInput-root': {
          backgroundColor: alpha(theme.palette.background.paper, 0.8),
          '&:hover': {
            backgroundColor: theme.palette.background.paper,
          },
          '&.Mui-focused': {
            backgroundColor: theme.palette.background.paper,
          },
        },
      }}
    />
  );
};

export default EnhancedSearchInput;
