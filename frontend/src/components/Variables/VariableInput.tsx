/**
 * Variable Input Component
 * Type-specific input for a single variable with validation
 */

import React from 'react';
import {
  Box,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  FormHelperText,
  Switch,
  FormControlLabel,
  Slider,
  Typography,
} from '@mui/material';
import type { VariableDefinition } from '@/types/scanConfig';

interface VariableInputProps {
  variable: VariableDefinition;
  value: any;
  onChange: (value: any) => void;
  error?: string;
}

export const VariableInput: React.FC<VariableInputProps> = ({
  variable,
  value,
  onChange,
  error,
}) => {
  const currentValue = value !== undefined && value !== null ? value : variable.default;

  // Number type with slider
  if (variable.type === 'number') {
    const { lower_bound, upper_bound } = variable.constraints || {};
    const numValue = Number(currentValue);

    if (lower_bound !== undefined && upper_bound !== undefined) {
      return (
        <Box>
          <Typography variant="subtitle2" gutterBottom>
            {variable.title}
          </Typography>
          <Typography variant="caption" color="text.secondary" gutterBottom display="block">
            {variable.description}
          </Typography>

          <Box sx={{ px: 1, pt: 1 }}>
            <Slider
              value={numValue}
              onChange={(_, v) => onChange(v)}
              min={lower_bound}
              max={upper_bound}
              marks
              valueLabelDisplay="auto"
              step={1}
            />
          </Box>

          <TextField
            fullWidth
            type="number"
            value={currentValue}
            onChange={(e) => onChange(e.target.value)}
            inputProps={{ min: lower_bound, max: upper_bound }}
            error={!!error}
            helperText={
              error || `Range: ${lower_bound}-${upper_bound} (Default: ${variable.default})`
            }
            size="small"
          />
        </Box>
      );
    }

    // Number without range
    return (
      <TextField
        fullWidth
        type="number"
        label={variable.title}
        value={currentValue}
        onChange={(e) => onChange(e.target.value)}
        error={!!error}
        helperText={error || `${variable.description} (Default: ${variable.default})`}
      />
    );
  }

  // Boolean type with switch
  if (variable.type === 'boolean') {
    const boolValue = currentValue === 'true' || currentValue === true || currentValue === '1';

    return (
      <Box>
        <FormControlLabel
          control={<Switch checked={boolValue} onChange={(e) => onChange(e.target.checked)} />}
          label={
            <Box>
              <Typography variant="subtitle2">{variable.title}</Typography>
              <Typography variant="caption" color="text.secondary">
                {variable.description}
              </Typography>
            </Box>
          }
        />
        {error && <FormHelperText error>{error}</FormHelperText>}
      </Box>
    );
  }

  // String type with choices (dropdown)
  if (variable.constraints?.choices && variable.constraints.choices.length > 0) {
    return (
      <FormControl fullWidth error={!!error}>
        <InputLabel>{variable.title}</InputLabel>
        <Select
          value={currentValue || ''}
          onChange={(e) => onChange(e.target.value)}
          label={variable.title}
        >
          {variable.constraints.choices.map((choice) => (
            <MenuItem key={choice} value={choice}>
              {choice}
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>{error || variable.description}</FormHelperText>
      </FormControl>
    );
  }

  // Default: text input
  const inputProps: any = {};
  if (variable.constraints?.match) {
    inputProps.pattern = variable.constraints.match;
  }

  return (
    <TextField
      fullWidth
      label={variable.title}
      value={currentValue || ''}
      onChange={(e) => onChange(e.target.value)}
      helperText={
        error ||
        `${variable.description} ${variable.default ? `(Default: ${variable.default})` : ''}`
      }
      error={!!error}
      inputProps={inputProps}
    />
  );
};
