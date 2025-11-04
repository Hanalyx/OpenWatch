/**
 * Template Selector Component
 * Dropdown for selecting templates with grouping
 */

import React from 'react';
import { Autocomplete, TextField, Box, Typography, CircularProgress } from '@mui/material';
import { Star as StarIcon } from '@mui/icons-material';
import { useTemplates } from '@/hooks/useTemplates';
import type { ScanTemplate } from '@/types/scanConfig';

// Extended type for grouped templates
type GroupedTemplate = ScanTemplate & { group: string };

interface TemplateSelectorProps {
  value?: string;
  onChange: (templateId: string | null) => void;
  framework?: string;
  disabled?: boolean;
}

export const TemplateSelector: React.FC<TemplateSelectorProps> = ({
  value,
  onChange,
  framework,
  disabled = false,
}) => {
  const { data: templates, isLoading } = useTemplates(framework ? { framework } : undefined);

  // Get current user from auth context (placeholder - implement based on your auth)
  const currentUser = { username: 'current_user' };

  // Group templates
  const myTemplates = templates?.filter((t) => t.created_by === currentUser.username) || [];
  const publicTemplates =
    templates?.filter((t) => t.is_public && t.created_by !== currentUser.username) || [];

  const groupedOptions: GroupedTemplate[] = [
    ...(myTemplates.length > 0
      ? myTemplates.map((t) => ({ ...t, group: 'My Templates' as const }))
      : []),
    ...(publicTemplates.length > 0
      ? publicTemplates.map((t) => ({ ...t, group: 'Public Templates' as const }))
      : []),
  ];

  const selectedTemplate = groupedOptions.find((t) => t.template_id === value);

  if (isLoading) {
    return (
      <Box display="flex" alignItems="center" gap={1}>
        <CircularProgress size={20} />
        <Typography variant="body2" color="text.secondary">
          Loading templates...
        </Typography>
      </Box>
    );
  }

  return (
    <Autocomplete<GroupedTemplate>
      fullWidth
      options={groupedOptions}
      groupBy={(option) => option.group}
      getOptionLabel={(option) => option.name}
      value={selectedTemplate || null}
      onChange={(_, newValue) => onChange(newValue?.template_id || null)}
      disabled={disabled}
      renderInput={(params) => <TextField {...params} label="Select Template" />}
      renderOption={(props, template) => (
        <li {...props}>
          <Box>
            <Box display="flex" alignItems="center" gap={0.5}>
              <Typography variant="body2">{template.name}</Typography>
              {template.is_default && <StarIcon fontSize="small" color="primary" />}
            </Box>
            <Typography variant="caption" color="text.secondary">
              {template.framework} {template.framework_version} •{' '}
              {Object.keys(template.variable_overrides).length} variables
            </Typography>
          </Box>
        </li>
      )}
    />
  );
};
