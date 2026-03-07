import React from 'react';
import { Box, Typography, IconButton } from '@mui/material';
import { ArrowBack } from '@mui/icons-material';
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
    </Box>
  );
};

export default AddHost;
