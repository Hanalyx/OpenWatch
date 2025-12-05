/**
 * Templates Page
 * List and manage scan configuration templates
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Grid,
  Button,
  TextField,
  InputAdornment,
  CircularProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import { Search as SearchIcon, Add as AddIcon } from '@mui/icons-material';
import {
  useTemplates,
  useDeleteTemplate,
  useCloneTemplate,
  useSetDefaultTemplate,
} from '@/hooks/useTemplates';
import { TemplateCard } from '@/components/Templates/TemplateCard';

export const TemplatesPage: React.FC = () => {
  const navigate = useNavigate();
  const { data: templates, isLoading, error } = useTemplates();
  const deleteTemplate = useDeleteTemplate();
  const cloneTemplate = useCloneTemplate();
  const setDefaultTemplate = useSetDefaultTemplate();

  const [searchQuery, setSearchQuery] = useState('');
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [cloneName, setCloneName] = useState('');

  // Get current user (placeholder - implement based on your auth)
  const currentUser = { username: 'current_user' };

  const handleEdit = (templateId: string) => {
    navigate(`/content/templates/${templateId}`);
  };

  const handleDelete = (templateId: string) => {
    setSelectedTemplate(templateId);
    setDeleteDialogOpen(true);
  };

  const confirmDelete = async () => {
    if (selectedTemplate) {
      await deleteTemplate.mutateAsync(selectedTemplate);
      setDeleteDialogOpen(false);
      setSelectedTemplate(null);
    }
  };

  const handleClone = (templateId: string, templateName: string) => {
    setSelectedTemplate(templateId);
    setCloneName(`${templateName} (Copy)`);
    setCloneDialogOpen(true);
  };

  const confirmClone = async () => {
    if (selectedTemplate && cloneName) {
      await cloneTemplate.mutateAsync({ id: selectedTemplate, newName: cloneName });
      setCloneDialogOpen(false);
      setSelectedTemplate(null);
      setCloneName('');
    }
  };

  const handleSetDefault = async (templateId: string) => {
    await setDefaultTemplate.mutateAsync(templateId);
  };

  const handleUse = (templateId: string) => {
    navigate('/scans/create', { state: { templateId } });
  };

  const myTemplates = templates?.filter((t) => t.created_by === currentUser.username) || [];
  const publicTemplates =
    templates?.filter((t) => t.is_public && t.created_by !== currentUser.username) || [];

  const filteredMyTemplates = myTemplates.filter((t) =>
    t.name.toLowerCase().includes(searchQuery.toLowerCase())
  );
  const filteredPublicTemplates = publicTemplates.filter((t) =>
    t.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">Failed to load templates. Please try again later.</Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            Scan Configuration Templates
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Save and reuse scan configurations
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => navigate('/content/templates/new')}
        >
          New Template
        </Button>
      </Box>

      <Box mb={4}>
        <TextField
          fullWidth
          placeholder="Search templates..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {/* My Templates */}
      <Box mb={4}>
        <Typography variant="h5" gutterBottom>
          My Templates ({myTemplates.length})
        </Typography>
        {filteredMyTemplates.length > 0 ? (
          <Grid container spacing={3}>
            {filteredMyTemplates.map((template) => (
              <Grid item xs={12} sm={6} md={4} key={template.template_id}>
                <TemplateCard
                  template={template}
                  onEdit={() => handleEdit(template.template_id)}
                  onDelete={() => handleDelete(template.template_id)}
                  onClone={() => handleClone(template.template_id, template.name)}
                  onSetDefault={() => handleSetDefault(template.template_id)}
                  onUse={() => handleUse(template.template_id)}
                />
              </Grid>
            ))}
          </Grid>
        ) : (
          <Box textAlign="center" py={4}>
            <Typography variant="body2" color="text.secondary">
              No personal templates found
            </Typography>
          </Box>
        )}
      </Box>

      {/* Public Templates */}
      <Box>
        <Typography variant="h5" gutterBottom>
          Public Templates ({publicTemplates.length})
        </Typography>
        {filteredPublicTemplates.length > 0 ? (
          <Grid container spacing={3}>
            {filteredPublicTemplates.map((template) => (
              <Grid item xs={12} sm={6} md={4} key={template.template_id}>
                <TemplateCard
                  template={template}
                  onClone={() => handleClone(template.template_id, template.name)}
                  onUse={() => handleUse(template.template_id)}
                  isPublic
                />
              </Grid>
            ))}
          </Grid>
        ) : (
          <Box textAlign="center" py={4}>
            <Typography variant="body2" color="text.secondary">
              No public templates available
            </Typography>
          </Box>
        )}
      </Box>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Template</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete this template? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={confirmDelete} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Clone Dialog */}
      <Dialog open={cloneDialogOpen} onClose={() => setCloneDialogOpen(false)}>
        <DialogTitle>Clone Template</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="New Template Name"
            value={cloneName}
            onChange={(e) => setCloneName(e.target.value)}
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCloneDialogOpen(false)}>Cancel</Button>
          <Button onClick={confirmClone} variant="contained" disabled={!cloneName}>
            Clone
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};
