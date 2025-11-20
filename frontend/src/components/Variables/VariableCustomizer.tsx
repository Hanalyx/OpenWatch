/**
 * Variable Customizer Component
 * Dynamic form for customizing XCCDF variables with validation
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Typography,
  Stack,
  CircularProgress,
  Alert,
} from '@mui/material';
import { ExpandMore as ExpandMoreIcon } from '@mui/icons-material';
import { useFrameworkVariables } from '@/hooks/useFrameworks';
import { frameworkService } from '@/services/frameworkService';
import { VariableInput } from './VariableInput';
import type { VariableDefinition, VariableDefaultValue } from '@/types/scanConfig';

interface VariableCustomizerProps {
  framework: string;
  version: string;
  initialValues?: Record<string, string>;
  onChange: (variables: Record<string, string>) => void;
  onValidate?: (isValid: boolean, errors: Record<string, string>) => void;
}

export const VariableCustomizer: React.FC<VariableCustomizerProps> = ({
  framework,
  version,
  initialValues = {},
  onChange,
  onValidate,
}) => {
  const { data: variables, isLoading, error } = useFrameworkVariables(framework, version);
  const [values, setValues] = useState<Record<string, string>>(initialValues);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [validating, setValidating] = useState(false);

  // Group variables by category
  const groupedVariables = useMemo(() => {
    if (!variables) return {};

    const groups: Record<string, VariableDefinition[]> = {};

    variables.forEach((variable) => {
      const category = variable.category || 'General';
      if (!groups[category]) {
        groups[category] = [];
      }
      groups[category].push(variable);
    });

    return groups;
  }, [variables]);

  useEffect(() => {
    setValues(initialValues);
  }, [initialValues]);

  // Validate variables on change - handles string, number, or boolean values
  const handleChange = async (varId: string, value: VariableDefaultValue) => {
    const newValues = { ...values, [varId]: String(value) };
    setValues(newValues);
    onChange(newValues);

    // Debounced validation
    setValidating(true);
    try {
      const validation = await frameworkService.validateVariables(framework, version, newValues);
      setErrors(validation.errors || {});
      onValidate?.(validation.valid, validation.errors || {});
    } catch (err) {
      console.error('Validation error:', err);
    } finally {
      setValidating(false);
    }
  };

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" p={4}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load variables for {framework} {version}
      </Alert>
    );
  }

  if (!variables || variables.length === 0) {
    return (
      <Alert severity="info">No customizable variables available for this framework version</Alert>
    );
  }

  return (
    <Box>
      {validating && (
        <Box display="flex" alignItems="center" gap={1} mb={2}>
          <CircularProgress size={16} />
          <Typography variant="caption" color="text.secondary">
            Validating variables...
          </Typography>
        </Box>
      )}

      {Object.entries(groupedVariables).map(([category, vars]) => (
        <Accordion key={category} defaultExpanded={category === 'General'}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="subtitle1" fontWeight="medium">
              {category} ({vars.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Stack spacing={3}>
              {vars.map((variable) => (
                <VariableInput
                  key={variable.id}
                  variable={variable}
                  value={values[variable.id]}
                  onChange={(v) => handleChange(variable.id, v)}
                  error={errors[variable.id]}
                />
              ))}
            </Stack>
          </AccordionDetails>
        </Accordion>
      ))}

      {Object.keys(errors).length > 0 && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {Object.keys(errors).length} validation error(s) found. Please correct the highlighted
          fields.
        </Alert>
      )}
    </Box>
  );
};
