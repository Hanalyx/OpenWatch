/**
 * Template Card Component
 * Displays template metadata with action buttons
 */

import React from 'react';
import {
  Card,
  CardHeader,
  CardContent,
  CardActions,
  Button,
  IconButton,
  Menu,
  MenuItem,
  Typography,
  Box,
  Chip,
  Stack,
} from '@mui/material';
import {
  MoreVert as MoreVertIcon,
  Star as StarIcon,
  Public as PublicIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  FileCopy as FileCopyIcon,
} from '@mui/icons-material';
import type { ScanTemplate } from '@/types/scanConfig';

interface TemplateCardProps {
  template: ScanTemplate;
  onEdit?: () => void;
  onDelete?: () => void;
  onClone?: () => void;
  onSetDefault?: () => void;
  onUse?: () => void;
  isPublic?: boolean;
}

export const TemplateCard: React.FC<TemplateCardProps> = ({
  template,
  onEdit,
  onDelete,
  onClone,
  onSetDefault,
  onUse,
  isPublic = false,
}) => {
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const menuOpen = Boolean(anchorEl);

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString();
  };

  return (
    <Card>
      <CardHeader
        title={
          <Box display="flex" alignItems="center" gap={1}>
            <Typography variant="h6" component="span">
              {template.name}
            </Typography>
            {template.is_default && (
              <StarIcon fontSize="small" color="primary" />
            )}
            {template.is_public && (
              <PublicIcon fontSize="small" color="action" />
            )}
          </Box>
        }
        subheader={`${template.framework} ${template.framework_version}`}
        action={
          <IconButton onClick={handleMenuOpen}>
            <MoreVertIcon />
          </IconButton>
        }
      />

      <CardContent>
        {template.description && (
          <Typography variant="body2" color="text.secondary" gutterBottom>
            {template.description}
          </Typography>
        )}

        <Box mt={2}>
          <Typography variant="caption" color="text.secondary">
            {Object.keys(template.variable_overrides).length} variables customized
          </Typography>
        </Box>

        {template.tags && template.tags.length > 0 && (
          <Stack direction="row" spacing={0.5} mt={1} flexWrap="wrap" gap={0.5}>
            {template.tags.map((tag) => (
              <Chip key={tag} label={tag} size="small" />
            ))}
          </Stack>
        )}

        <Box mt={2}>
          <Typography variant="caption" color="text.secondary">
            Created: {formatDate(template.created_at)}
          </Typography>
        </Box>
      </CardContent>

      <CardActions>
        {onUse && (
          <Button size="small" variant="contained" onClick={onUse}>
            Use Template
          </Button>
        )}
        {onEdit && !isPublic && (
          <Button size="small" startIcon={<EditIcon />} onClick={onEdit}>
            Edit
          </Button>
        )}
        {onClone && (
          <Button size="small" startIcon={<FileCopyIcon />} onClick={onClone}>
            Clone
          </Button>
        )}
      </CardActions>

      <Menu anchorEl={anchorEl} open={menuOpen} onClose={handleMenuClose}>
        {onEdit && !isPublic && (
          <MenuItem
            onClick={() => {
              onEdit();
              handleMenuClose();
            }}
          >
            <EditIcon fontSize="small" sx={{ mr: 1 }} />
            Edit
          </MenuItem>
        )}
        {onClone && (
          <MenuItem
            onClick={() => {
              onClone();
              handleMenuClose();
            }}
          >
            <FileCopyIcon fontSize="small" sx={{ mr: 1 }} />
            Clone
          </MenuItem>
        )}
        {onSetDefault && !template.is_default && !isPublic && (
          <MenuItem
            onClick={() => {
              onSetDefault();
              handleMenuClose();
            }}
          >
            <StarIcon fontSize="small" sx={{ mr: 1 }} />
            Set as Default
          </MenuItem>
        )}
        {onDelete && !isPublic && (
          <MenuItem
            onClick={() => {
              onDelete();
              handleMenuClose();
            }}
            sx={{ color: 'error.main' }}
          >
            <DeleteIcon fontSize="small" sx={{ mr: 1 }} />
            Delete
          </MenuItem>
        )}
      </Menu>
    </Card>
  );
};
