/**
 * Frameworks Page
 * Browse and discover compliance frameworks
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Grid,
  TextField,
  InputAdornment,
  CircularProgress,
  Alert,
} from '@mui/material';
import { Search as SearchIcon } from '@mui/icons-material';
import { useFrameworks } from '@/hooks/useFrameworks';
import { FrameworkCard } from '@/components/frameworks/FrameworkCard';
import type { Framework } from '@/types/scanConfig';

export const FrameworksPage: React.FC = () => {
  const navigate = useNavigate();
  const { data: frameworks, isLoading, error } = useFrameworks();
  const [searchQuery, setSearchQuery] = useState('');

  const handleSelectFramework = (framework: Framework) => {
    const defaultVersion = framework.versions[0];
    navigate(`/content/frameworks/${framework.framework}/${defaultVersion}`);
  };

  const filteredFrameworks = frameworks?.filter((f) => {
    const query = searchQuery.toLowerCase();
    return (
      f.display_name.toLowerCase().includes(query) ||
      f.framework.toLowerCase().includes(query) ||
      f.description.toLowerCase().includes(query)
    );
  });

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
        <Alert severity="error">Failed to load frameworks. Please try again later.</Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Box mb={4}>
        <Typography variant="h4" component="h1" gutterBottom>
          Compliance Frameworks
        </Typography>
        <Typography variant="body1" color="text.secondary" gutterBottom>
          Browse available compliance frameworks and create scan templates
        </Typography>
      </Box>

      <Box mb={4}>
        <TextField
          fullWidth
          placeholder="Search frameworks..."
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

      {filteredFrameworks && filteredFrameworks.length > 0 ? (
        <Grid container spacing={3}>
          {filteredFrameworks.map((framework) => (
            <Grid item xs={12} sm={6} md={4} key={framework.framework}>
              <FrameworkCard framework={framework} onSelect={handleSelectFramework} />
            </Grid>
          ))}
        </Grid>
      ) : (
        <Box textAlign="center" py={8}>
          <Typography variant="h6" color="text.secondary">
            No frameworks found
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {searchQuery ? 'Try a different search query' : 'No frameworks available'}
          </Typography>
        </Box>
      )}

      {frameworks && (
        <Box mt={4} textAlign="center">
          <Typography variant="body2" color="text.secondary">
            Showing {filteredFrameworks?.length || 0} of {frameworks.length} frameworks
          </Typography>
        </Box>
      )}
    </Container>
  );
};
