import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  IconButton,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  Tabs,
  Tab,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Security,
  CheckCircle,
  BugReport,
  Settings,
  Save,
  Cancel,
} from '@mui/icons-material';

/**
 * Scan template configuration
 * Stores reusable scan configurations for different scopes
 */
interface ScanTemplate {
  id: string;
  name: string;
  description: string;
  contentId: number;
  profileId: string;
  // Scan options - flexible configuration object supporting various scan parameters
  // May include: timeout, retries, notifications, scheduling, custom variables, etc.
  scanOptions: Record<string, string | number | boolean | string[]>;
  scope: 'system' | 'group' | 'host';
  scopeId?: string;
  isDefault: boolean;
  createdBy: string;
  createdAt: string;
}

interface ScanTemplateManagerProps {
  open: boolean;
  onClose: () => void;
  hostId?: string;
  groupId?: string;
}

const ScanTemplateManager: React.FC<ScanTemplateManagerProps> = ({
  open,
  onClose,
  hostId,
  groupId,
}) => {
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  const [selectedTab, setSelectedTab] = useState(0);
  const [editingTemplate, setEditingTemplate] = useState<ScanTemplate | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    contentId: 1,
    profileId: '',
    scope: 'system' as 'system' | 'group' | 'host',
    isDefault: false,
  });

  // Fetch templates when dialog opens
  // ESLint disable: fetchTemplates function is not memoized to avoid complex dependency chain
  useEffect(() => {
    if (open) {
      fetchTemplates();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const fetchTemplates = async () => {
    try {
      setLoading(true);
      const endpoint = hostId
        ? `/api/scans/templates/host/${hostId}`
        : groupId
          ? `/api/scans/templates/group/${groupId}`
          : '/api/scans/templates';

      const response = await fetch(endpoint, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setTemplates(data.templates || []);
      }
    } catch (err) {
      console.error('Failed to fetch templates:', err);
      setError('Failed to load scan templates');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveTemplate = async () => {
    try {
      setLoading(true);
      const templateData = {
        ...formData,
        scopeId: formData.scope === 'host' ? hostId : formData.scope === 'group' ? groupId : null,
      };

      const response = await fetch('/api/scans/templates', {
        method: editingTemplate ? 'PUT' : 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
        body: JSON.stringify(
          editingTemplate ? { ...templateData, id: editingTemplate.id } : templateData
        ),
      });

      if (response.ok) {
        await fetchTemplates();
        setShowCreateForm(false);
        setEditingTemplate(null);
        resetForm();
      } else {
        throw new Error('Failed to save template');
      }
    } catch (err) {
      console.error('Failed to save template:', err);
      setError('Failed to save scan template');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteTemplate = async (templateId: string) => {
    if (!confirm('Are you sure you want to delete this scan template?')) {
      return;
    }

    try {
      const response = await fetch(`/api/scans/templates/${templateId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (response.ok) {
        await fetchTemplates();
      } else {
        throw new Error('Failed to delete template');
      }
    } catch (err) {
      console.error('Failed to delete template:', err);
      setError('Failed to delete scan template');
    }
  };

  const handleEditTemplate = (template: ScanTemplate) => {
    setEditingTemplate(template);
    setFormData({
      name: template.name,
      description: template.description,
      contentId: template.contentId,
      profileId: template.profileId,
      scope: template.scope,
      isDefault: template.isDefault,
    });
    setShowCreateForm(true);
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      contentId: 1,
      profileId: '',
      scope: hostId ? 'host' : groupId ? 'group' : 'system',
      isDefault: false,
    });
  };

  const _getTemplateIcon = (template: ScanTemplate) => {
    if (template.name.toLowerCase().includes('security')) return <Security />;
    if (template.name.toLowerCase().includes('compliance')) return <CheckCircle />;
    if (template.name.toLowerCase().includes('vulnerability')) return <BugReport />;
    return <Settings />;
  };

  const templatesByScope = {
    system: templates.filter((t) => t.scope === 'system'),
    group: templates.filter((t) => t.scope === 'group'),
    host: templates.filter((t) => t.scope === 'host'),
  };

  const tabLabels = [
    { label: 'System Templates', count: templatesByScope.system.length },
    ...(groupId ? [{ label: 'Group Templates', count: templatesByScope.group.length }] : []),
    ...(hostId ? [{ label: 'Host Templates', count: templatesByScope.host.length }] : []),
  ];

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="h6">Scan Template Manager</Typography>
          <Button
            startIcon={<AddIcon />}
            variant="contained"
            onClick={() => {
              resetForm();
              setShowCreateForm(true);
            }}
            disabled={loading}
          >
            Create Template
          </Button>
        </Box>
      </DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {showCreateForm ? (
          <Box sx={{ mb: 3, p: 2, border: 1, borderColor: 'divider', borderRadius: 1 }}>
            <Typography variant="h6" gutterBottom>
              {editingTemplate ? 'Edit Template' : 'Create New Template'}
            </Typography>

            <TextField
              fullWidth
              label="Template Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              margin="normal"
              required
            />

            <TextField
              fullWidth
              label="Description"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              margin="normal"
              multiline
              rows={2}
            />

            <FormControl fullWidth margin="normal">
              <InputLabel>Scope</InputLabel>
              <Select
                value={formData.scope}
                label="Scope"
                onChange={(e) =>
                  setFormData({ ...formData, scope: e.target.value as 'system' | 'group' | 'host' })
                }
              >
                <MenuItem value="system">System-wide (all hosts)</MenuItem>
                {groupId && <MenuItem value="group">Group-specific</MenuItem>}
                {hostId && <MenuItem value="host">Host-specific</MenuItem>}
              </Select>
            </FormControl>

            <TextField
              fullWidth
              label="Profile ID"
              value={formData.profileId}
              onChange={(e) => setFormData({ ...formData, profileId: e.target.value })}
              margin="normal"
              placeholder="e.g., xccdf_org.ssgproject.content_profile_cui"
              required
            />

            <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
              <Button
                variant="contained"
                startIcon={<Save />}
                onClick={handleSaveTemplate}
                disabled={loading || !formData.name || !formData.profileId}
              >
                {editingTemplate ? 'Update' : 'Create'}
              </Button>
              <Button
                variant="outlined"
                startIcon={<Cancel />}
                onClick={() => {
                  setShowCreateForm(false);
                  setEditingTemplate(null);
                  resetForm();
                }}
              >
                Cancel
              </Button>
            </Box>
          </Box>
        ) : null}

        <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
          {tabLabels.map((tab, index) => (
            <Tab key={index} label={`${tab.label} (${tab.count})`} />
          ))}
        </Tabs>

        <Box sx={{ mt: 2 }}>
          {selectedTab === 0 && (
            <TemplateList
              templates={templatesByScope.system}
              onEdit={handleEditTemplate}
              onDelete={handleDeleteTemplate}
              loading={loading}
            />
          )}
          {selectedTab === 1 && groupId && (
            <TemplateList
              templates={templatesByScope.group}
              onEdit={handleEditTemplate}
              onDelete={handleDeleteTemplate}
              loading={loading}
            />
          )}
          {((selectedTab === 1 && !groupId) || selectedTab === 2) && hostId && (
            <TemplateList
              templates={templatesByScope.host}
              onEdit={handleEditTemplate}
              onDelete={handleDeleteTemplate}
              loading={loading}
            />
          )}
        </Box>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

interface TemplateListProps {
  templates: ScanTemplate[];
  onEdit: (template: ScanTemplate) => void;
  onDelete: (templateId: string) => void;
  loading: boolean;
}

const TemplateList: React.FC<TemplateListProps> = ({ templates, onEdit, onDelete, loading }) => {
  const getTemplateIcon = (template: ScanTemplate) => {
    if (template.name.toLowerCase().includes('security')) return <Security />;
    if (template.name.toLowerCase().includes('compliance')) return <CheckCircle />;
    if (template.name.toLowerCase().includes('vulnerability')) return <BugReport />;
    return <Settings />;
  };

  if (templates.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <Typography variant="body2" color="text.secondary">
          No templates found. Create your first template to get started.
        </Typography>
      </Box>
    );
  }

  return (
    <List>
      {templates.map((template, index) => (
        <React.Fragment key={template.id}>
          {index > 0 && <Divider />}
          <ListItem sx={{ py: 2 }}>
            <ListItemIcon>{getTemplateIcon(template)}</ListItemIcon>
            <ListItemText
              primary={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography variant="subtitle1">{template.name}</Typography>
                  {template.isDefault && <Chip label="Default" size="small" color="primary" />}
                </Box>
              }
              secondary={
                <Box>
                  <Typography variant="body2" color="text.secondary">
                    {template.description}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Profile: {template.profileId}
                  </Typography>
                </Box>
              }
            />
            <ListItemSecondaryAction>
              <IconButton
                edge="end"
                onClick={() => onEdit(template)}
                disabled={loading}
                sx={{ mr: 1 }}
              >
                <EditIcon />
              </IconButton>
              <IconButton
                edge="end"
                onClick={() => onDelete(template.id)}
                disabled={loading}
                color="error"
              >
                <DeleteIcon />
              </IconButton>
            </ListItemSecondaryAction>
          </ListItem>
        </React.Fragment>
      ))}
    </List>
  );
};

export default ScanTemplateManager;
