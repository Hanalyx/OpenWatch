/**
 * Framework Detail Page
 * View framework metadata, variables, and rules
 */

import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Breadcrumbs,
  Link,
  Tabs,
  Tab,
  Paper,
  Grid,
  Chip,
  Button,
  CircularProgress,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  Home as HomeIcon,
  Article as ArticleIcon,
  Settings as SettingsIcon,
  Rule as RuleIcon,
  Add as AddIcon,
} from '@mui/icons-material';
import { useFrameworkDetails, useFrameworkVariables } from '@/hooks/useFrameworks';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => {
  return (
    <div role="tabpanel" hidden={value !== index}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
};

export const FrameworkDetailPage: React.FC = () => {
  const { framework, version } = useParams<{ framework: string; version: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);

  const { data: details, isLoading: loadingDetails, error: detailsError } = useFrameworkDetails(
    framework || '',
    version || ''
  );
  const { data: variables, isLoading: loadingVariables } = useFrameworkVariables(
    framework || '',
    version || ''
  );

  const handleCreateTemplate = () => {
    navigate('/content/templates/new', {
      state: { framework, version },
    });
  };

  if (loadingDetails) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (detailsError || !details) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">
          Failed to load framework details. Please try again later.
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Breadcrumbs */}
      <Breadcrumbs sx={{ mb: 2 }}>
        <Link
          underline="hover"
          color="inherit"
          href="/"
          onClick={(e) => {
            e.preventDefault();
            navigate('/');
          }}
          sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
        >
          <HomeIcon fontSize="small" />
          Home
        </Link>
        <Link
          underline="hover"
          color="inherit"
          href="/content"
          onClick={(e) => {
            e.preventDefault();
            navigate('/content');
          }}
        >
          Content
        </Link>
        <Link
          underline="hover"
          color="inherit"
          href="/content/frameworks"
          onClick={(e) => {
            e.preventDefault();
            navigate('/content/frameworks');
          }}
        >
          Frameworks
        </Link>
        <Typography color="text.primary">{details.display_name}</Typography>
      </Breadcrumbs>

      {/* Header */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={8}>
            <Typography variant="h4" gutterBottom>
              {details.display_name}
            </Typography>
            <Typography variant="body1" color="text.secondary" gutterBottom>
              {details.description}
            </Typography>
            <Box mt={2} display="flex" gap={1} flexWrap="wrap">
              <Chip label={`Version: ${version}`} color="primary" />
              <Chip label={`${details.rule_count} Rules`} variant="outlined" />
              <Chip label={`${details.variable_count} Variables`} variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={4} textAlign="right">
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleCreateTemplate}
              size="large"
            >
              Create Template
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Tabs */}
      <Paper>
        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)}>
          <Tab icon={<ArticleIcon />} label="Overview" iconPosition="start" />
          <Tab
            icon={<SettingsIcon />}
            label={`Variables (${variables?.length || 0})`}
            iconPosition="start"
          />
          <Tab
            icon={<RuleIcon />}
            label={`Rules (${details.rule_count})`}
            iconPosition="start"
          />
        </Tabs>

        <TabPanel value={activeTab} index={0}>
          <Box px={3}>
            <Typography variant="h6" gutterBottom>
              Framework Information
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" color="text.secondary">
                  Framework ID
                </Typography>
                <Typography variant="body1">{framework}</Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="subtitle2" color="text.secondary">
                  Version
                </Typography>
                <Typography variant="body1">{version}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">
                  Description
                </Typography>
                <Typography variant="body1">{details.description}</Typography>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        <TabPanel value={activeTab} index={1}>
          <Box px={3}>
            {loadingVariables ? (
              <Box display="flex" justifyContent="center" py={4}>
                <CircularProgress />
              </Box>
            ) : variables && variables.length > 0 ? (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Variable</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Default</TableCell>
                      <TableCell>Description</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {variables.map((variable) => (
                      <TableRow key={variable.id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {variable.title}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {variable.id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={variable.type} size="small" />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {String(variable.default)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {variable.description}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Box textAlign="center" py={4}>
                <Typography color="text.secondary">
                  No variables available for this framework
                </Typography>
              </Box>
            )}
          </Box>
        </TabPanel>

        <TabPanel value={activeTab} index={2}>
          <Box px={3}>
            <Typography variant="body1" color="text.secondary">
              {details.rule_count} compliance rules available. Use the Compliance Rules page to
              view detailed rule information.
            </Typography>
            <Box mt={2}>
              <Button
                variant="outlined"
                onClick={() =>
                  navigate(`/content/rules?framework=${framework}&version=${version}`)
                }
              >
                View All Rules
              </Button>
            </Box>
          </Box>
        </TabPanel>
      </Paper>
    </Container>
  );
};
