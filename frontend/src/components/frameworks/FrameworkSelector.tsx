/**
 * Framework Selector Component
 * Dropdown for selecting framework and version
 */

import React, { useState, useEffect, type SyntheticEvent } from 'react';
import { Box, Autocomplete, TextField, CircularProgress } from '@mui/material';
import { useFrameworks } from '@/hooks/useFrameworks';
import { type Framework } from '@/types/scanConfig';

interface FrameworkSelectorProps {
  value?: { framework: string; version: string };
  onChange: (framework: string, version: string) => void;
  disabled?: boolean;
}

export const FrameworkSelector: React.FC<FrameworkSelectorProps> = ({
  value,
  onChange,
  disabled = false,
}) => {
  const { data: frameworks, isLoading } = useFrameworks();
  const [selectedFramework, setSelectedFramework] = useState(value?.framework || '');
  const [selectedVersion, setSelectedVersion] = useState(value?.version || '');

  const selectedFrameworkData = frameworks?.find((f) => f.framework === selectedFramework);

  useEffect(() => {
    if (value) {
      setSelectedFramework(value.framework);
      setSelectedVersion(value.version);
    }
  }, [value]);

  // Handle framework selection change from Autocomplete
  // MUI Autocomplete provides SyntheticEvent and selected value
  const handleFrameworkChange = (_: SyntheticEvent, newValue: Framework | null) => {
    const newFramework = newValue?.framework || '';
    const defaultVersion = newValue?.versions?.[0] || '';

    setSelectedFramework(newFramework);
    setSelectedVersion(defaultVersion);

    if (newFramework && defaultVersion) {
      onChange(newFramework, defaultVersion);
    }
  };

  // Handle version selection change from Autocomplete
  // MUI Autocomplete for string options provides SyntheticEvent and string value
  const handleVersionChange = (_: SyntheticEvent, newValue: string | null) => {
    const newVersion = newValue || '';
    setSelectedVersion(newVersion);

    if (selectedFramework && newVersion) {
      onChange(selectedFramework, newVersion);
    }
  };

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" p={2}>
        <CircularProgress size={24} />
      </Box>
    );
  }

  return (
    <Box display="flex" gap={2} flexDirection={{ xs: 'column', sm: 'row' }}>
      <Autocomplete
        sx={{ flex: 1 }}
        options={frameworks || []}
        getOptionLabel={(f) => f.display_name}
        value={selectedFrameworkData || null}
        onChange={handleFrameworkChange}
        disabled={disabled}
        renderInput={(params) => <TextField {...params} label="Framework" required />}
      />

      {selectedFramework && selectedFrameworkData && (
        <Autocomplete
          sx={{ flex: 1 }}
          options={selectedFrameworkData.versions || []}
          value={selectedVersion || null}
          onChange={handleVersionChange}
          disabled={disabled}
          renderInput={(params) => <TextField {...params} label="Version" required />}
        />
      )}
    </Box>
  );
};
