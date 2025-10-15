/**
 * Template Editor Page
 * Create and edit scan configuration templates
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Paper,
  TextField,
  Button,
  Checkbox,
  FormControlLabel,
  Stack,
  Chip,
  CircularProgress,
  Alert,
  Divider,
} from '@mui/material';
import { Save as SaveIcon, Cancel as CancelIcon } from '@mui/icons-material';
import { useTemplate, useCreateTemplate, useUpdateTemplate } from '@/hooks/useTemplates';
import { FrameworkSelector } from '@/components/Frameworks/FrameworkSelector';
import { VariableCustomizer } from '@/components/Variables/VariableCustomizer';
import type { CreateTemplateRequest } from '@/types/scanConfig';

export const TemplateEditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const isEditMode = !!id;

  const { data: existingTemplate, isLoading: loadingTemplate } = useTemplate(id || '');
  const createTemplate = useCreateTemplate();
  const updateTemplate = useUpdateTemplate();

  // Get framework/version from navigation state (when creating from framework detail page)
  const initialFramework = location.state?.framework;
  const initialVersion = location.state?.version;

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [framework, setFramework] = useState(initialFramework || '');
  const [version, setVersion] = useState(initialVersion || '');
  const [variableOverrides, setVariableOverrides] = useState<Record<string, string>>({});
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [isDefault, setIsDefault] = useState(false);
  const [isPublic, setIsPublic] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [isValid, setIsValid] = useState(true);

  // Load existing template data
  useEffect(() => {
    if (existingTemplate) {
      setName(existingTemplate.name);
      setDescription(existingTemplate.description || '');
      setFramework(existingTemplate.framework);
      setVersion(existingTemplate.framework_version);
      setVariableOverrides(existingTemplate.variable_overrides || {});
      setTags(existingTemplate.tags || []);
      setIsDefault(existingTemplate.is_default);
      setIsPublic(existingTemplate.is_public);
    }
  }, [existingTemplate]);

  const handleFrameworkChange = (newFramework: string, newVersion: string) => {
    setFramework(newFramework);
    setVersion(newVersion);
    // Reset variables when framework changes
    if (newFramework !== framework) {
      setVariableOverrides({});
    }
  };

  const handleVariablesChange = (variables: Record<string, string>) => {
    setVariableOverrides(variables);
  };

  const handleValidation = (valid: boolean, errors: Record<string, string>) => {
    setIsValid(valid);
    setValidationErrors(errors);
  };

  const handleAddTag = () => {
    if (tagInput && !tags.includes(tagInput)) {
      setTags([...tags, tagInput]);
      setTagInput('');
    }
  };

  const handleDeleteTag = (tagToDelete: string) => {
    setTags(tags.filter((tag) => tag !== tagToDelete));
  };

  const handleSubmit = async () => {
    if (!name || !framework || !version) {
      return;
    }

    if (!isValid) {
      alert('Please fix validation errors before saving');
      return;
    }

    const templateData: CreateTemplateRequest = {
      name,
      description,
      framework,
      framework_version: version,
      target_type: 'ssh_host', // Default target type
      variable_overrides: variableOverrides,
      tags,
      is_public: isPublic,
    };

    try {
      if (isEditMode && id) {
        await updateTemplate.mutateAsync({ id, data: templateData });
      } else {
        await createTemplate.mutateAsync(templateData);
      }
      navigate('/content/templates');
    } catch (error) {
      console.error('Failed to save template:', error);
    }
  };

  const handleCancel = () => {
    navigate('/content/templates');
  };

  if (isEditMode && loadingTemplate) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        {isEditMode ? 'Edit Template' : 'New Template'}
      </Typography>
      <Typography variant="body1" color="text.secondary" gutterBottom>
        {isEditMode
          ? 'Update your scan configuration template'
          : 'Create a reusable scan configuration template'}
      </Typography>

      <Paper sx={{ p: 3, mt: 3 }}>
        <Stack spacing={3}>
          {/* Basic Information */}
          <TextField
            fullWidth
            required
            label="Template Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., NIST 800-53 rev5 - Production Servers"
          />

          <TextField
            fullWidth
            multiline
            rows={3}
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe when to use this template..."
          />

          <Divider />

          {/* Framework Selection */}
          <Box>
            <Typography variant="subtitle1" gutterBottom fontWeight="medium">
              Framework & Version
            </Typography>
            <FrameworkSelector
              value={framework && version ? { framework, version } : undefined}
              onChange={handleFrameworkChange}
              disabled={isEditMode} // Can't change framework in edit mode
            />
          </Box>

          {/* Variable Customization */}
          {framework && version && (
            <Box>
              <Typography variant="subtitle1" gutterBottom fontWeight="medium">
                Variable Customization
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Customize default variable values for this template
              </Typography>
              <VariableCustomizer
                framework={framework}
                version={version}
                initialValues={variableOverrides}
                onChange={handleVariablesChange}
                onValidate={handleValidation}
              />
            </Box>
          )}

          <Divider />

          {/* Tags */}
          <Box>
            <Typography variant="subtitle1" gutterBottom fontWeight="medium">
              Tags
            </Typography>
            <Box display="flex" gap={1} mb={1} flexWrap="wrap">
              {tags.map((tag) => (
                <Chip
                  key={tag}
                  label={tag}
                  onDelete={() => handleDeleteTag(tag)}
                  size="small"
                />
              ))}
            </Box>
            <Box display="flex" gap={1}>
              <TextField
                size="small"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                placeholder="Add tag..."
                onKeyPress={(e) => e.key === 'Enter' && handleAddTag()}
              />
              <Button size="small" onClick={handleAddTag}>
                Add
              </Button>
            </Box>
          </Box>

          <Divider />

          {/* Options */}
          <Box>
            <Typography variant="subtitle1" gutterBottom fontWeight="medium">
              Options
            </Typography>
            <Stack spacing={1}>
              <FormControlLabel
                control={
                  <Checkbox checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />
                }
                label="Set as my default template"
              />
              <FormControlLabel
                control={
                  <Checkbox checked={isPublic} onChange={(e) => setIsPublic(e.target.checked)} />
                }
                label="Make this template public"
              />
            </Stack>
          </Box>

          {/* Validation Errors */}
          {!isValid && Object.keys(validationErrors).length > 0 && (
            <Alert severity="error">
              {Object.keys(validationErrors).length} validation error(s) found. Please correct the
              highlighted fields.
            </Alert>
          )}

          {/* Actions */}
          <Box display="flex" gap={2} justifyContent="flex-end">
            <Button
              variant="outlined"
              startIcon={<CancelIcon />}
              onClick={handleCancel}
            >
              Cancel
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSubmit}
              disabled={!name || !framework || !version || !isValid}
            >
              {isEditMode ? 'Update Template' : 'Create Template'}
            </Button>
          </Box>
        </Stack>
      </Paper>
    </Container>
  );
};
