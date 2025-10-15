/**
 * Framework Card Component
 * Displays framework metadata in a card layout
 */

import React from 'react';
import {
  Card,
  CardContent,
  CardActionArea,
  Typography,
  Box,
  Chip,
  Stack,
} from '@mui/material';
import { AccountTree as FrameworkIcon } from '@mui/icons-material';
import type { Framework } from '@/types/scanConfig';

interface FrameworkCardProps {
  framework: Framework;
  onSelect: (framework: Framework) => void;
}

export const FrameworkCard: React.FC<FrameworkCardProps> = ({ framework, onSelect }) => {
  return (
    <Card>
      <CardActionArea onClick={() => onSelect(framework)}>
        <CardContent>
          <Box display="flex" alignItems="center" gap={1} mb={1}>
            <FrameworkIcon color="primary" />
            <Typography variant="h6" component="div">
              {framework.display_name}
            </Typography>
          </Box>

          <Typography variant="body2" color="text.secondary" mb={2}>
            {framework.description}
          </Typography>

          <Stack direction="row" spacing={1} flexWrap="wrap" gap={1}>
            <Chip
              label={`${framework.rule_count} rules`}
              size="small"
              color="primary"
              variant="outlined"
            />
            <Chip
              label={`${framework.variable_count} variables`}
              size="small"
              color="secondary"
              variant="outlined"
            />
            <Chip
              label={`${framework.versions.length} version${framework.versions.length > 1 ? 's' : ''}`}
              size="small"
              variant="outlined"
            />
          </Stack>

          {framework.versions.length > 0 && (
            <Box mt={2}>
              <Typography variant="caption" color="text.secondary">
                Versions: {framework.versions.join(', ')}
              </Typography>
            </Box>
          )}
        </CardContent>
      </CardActionArea>
    </Card>
  );
};
