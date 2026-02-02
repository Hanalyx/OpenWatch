import React from 'react';
import { Box, Typography, IconButton, Paper, Card, CardContent } from '@mui/material';
import Grid from '@mui/material/Grid';
import { ArrowBack, Computer, Security, Schedule, Description } from '@mui/icons-material';
import { StatCard } from '../../components/design-system';
import { useAddHostForm } from './hooks/useAddHostForm';
import { QuickAddHostForm } from './components/QuickAddHostForm';
import { AdvancedAddHostForm } from './components/AdvancedAddHostForm';

const AddHost: React.FC = () => {
  const {
    navigate,
    // UI State
    activeStep,
    quickMode,
    setQuickMode,
    testingConnection,
    connectionStatus,
    connectionTestResults,
    showPassword,
    setShowPassword,
    showAdvanced,
    setShowAdvanced,
    // Auth state
    sshKeyValidation,
    authMethodLocked,
    systemCredentials,
    editingAuth,
    // Form data
    formData,
    // Handlers
    handleInputChange,
    handleNext,
    handleBack,
    handleTestConnection,
    handleSubmit,
    handleAuthMethodChange,
    validateSshKey,
    toggleAuthEdit,
  } = useAddHostForm();

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <IconButton onClick={() => navigate('/hosts')}>
          <ArrowBack />
        </IconButton>
        <Typography variant="h4" fontWeight="bold">
          Add New Host
        </Typography>
      </Box>

      {/* Quick Stats */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            title="Total Hosts"
            value="4"
            icon={<Computer />}
            color="primary"
            subtitle="Currently managed"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            title="Available Profiles"
            value="8"
            icon={<Security />}
            color="success"
            subtitle="Compliance standards"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            title="Scan Queue"
            value="2"
            icon={<Schedule />}
            color="warning"
            subtitle="Pending scans"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            title="Templates"
            value="5"
            icon={<Description />}
            color="info"
            subtitle="Saved configurations"
          />
        </Grid>
      </Grid>

      {/* Main Form */}
      {quickMode ? (
        <QuickAddHostForm
          formData={formData}
          showPassword={showPassword}
          connectionStatus={connectionStatus}
          connectionTestResults={connectionTestResults}
          testingConnection={testingConnection}
          sshKeyValidation={sshKeyValidation}
          authMethodLocked={authMethodLocked}
          systemCredentials={systemCredentials}
          editingAuth={editingAuth}
          onInputChange={handleInputChange}
          onTestConnection={handleTestConnection}
          onSubmit={handleSubmit}
          onAuthMethodChange={handleAuthMethodChange}
          onToggleAuthEdit={toggleAuthEdit}
          onValidateSshKey={validateSshKey}
          onShowPasswordToggle={setShowPassword}
          onModeChange={setQuickMode}
          onCancel={() => navigate('/hosts')}
        />
      ) : (
        <AdvancedAddHostForm
          formData={formData}
          activeStep={activeStep}
          showPassword={showPassword}
          showAdvanced={showAdvanced}
          connectionStatus={connectionStatus}
          testingConnection={testingConnection}
          onInputChange={handleInputChange}
          onNext={handleNext}
          onBack={handleBack}
          onTestConnection={handleTestConnection}
          onSubmit={handleSubmit}
          onShowPasswordToggle={setShowPassword}
          onShowAdvancedToggle={setShowAdvanced}
          onModeChange={setQuickMode}
          onCancel={() => navigate('/hosts')}
        />
      )}

      {/* Templates Section */}
      <Paper sx={{ mt: 3, p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Quick Start Templates
        </Typography>
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <Card
              variant="outlined"
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <CardContent>
                <Typography variant="subtitle2" color="primary">
                  Linux Web Server
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Ubuntu/RHEL with CIS Level 2
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <Card
              variant="outlined"
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <CardContent>
                <Typography variant="subtitle2" color="primary">
                  Database Server
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  PostgreSQL/MySQL with STIG
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <Card
              variant="outlined"
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <CardContent>
                <Typography variant="subtitle2" color="primary">
                  Container Host
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Docker/K8s with CIS Benchmark
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <Card
              variant="outlined"
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <CardContent>
                <Typography variant="subtitle2" color="primary">
                  Windows Server
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Windows 2019/2022 with STIG
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
};

export default AddHost;
