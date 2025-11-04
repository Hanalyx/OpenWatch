import React, { useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Chip,
  Alert,
} from '@mui/material';
import { PlayArrow, Group, Computer, Security } from '@mui/icons-material';
import ScanProgressDialog from '../host-groups/ScanProgressDialog';

/**
 * Demo component showcasing the Host Group Scan Progress functionality
 * This demonstrates the scan progress dialog with mock data
 */
const ScanProgressDemo: React.FC = () => {
  const [showScanProgress, setShowScanProgress] = useState(false);

  // Mock group data for demo
  const mockGroup = {
    id: 1,
    name: 'RHEL 8 STIG Compliance',
    host_count: 3,
    scap_content_id: 1,
    default_profile_id: 'stig_rhel8',
    scap_content_name: 'RHEL 8 STIG Content',
  };

  const mockSessionId = 'demo-session-12345';

  const handleStartDemo = () => {
    setShowScanProgress(true);
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1200, margin: '0 auto' }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Host Group Scan Progress Demo
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }}>
        This demo showcases the enhanced Group Scan Progress functionality. Click "Start Demo Scan"
        to see the real-time progress interface in action.
      </Alert>

      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Mock Group Card */}
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <Group color="primary" />
                <Typography variant="h6">{mockGroup.name}</Typography>
              </Box>

              <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                <Chip
                  icon={<Computer />}
                  label={`${mockGroup.host_count} hosts`}
                  size="small"
                  variant="outlined"
                />
                <Chip
                  icon={<Security />}
                  label={mockGroup.scap_content_name}
                  size="small"
                  color="secondary"
                  variant="outlined"
                />
                <Chip
                  icon={<PlayArrow />}
                  label="Scan Ready"
                  size="small"
                  color="success"
                  variant="outlined"
                />
              </Box>

              <Button
                variant="contained"
                startIcon={<PlayArrow />}
                onClick={handleStartDemo}
                fullWidth
                size="large"
                sx={{ mt: 2 }}
              >
                Start Demo Scan
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Features Overview */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Scan Progress Features
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Typography variant="body2">
                ✅ <strong>Real-time Updates</strong> - Live progress tracking every 3 seconds
              </Typography>
              <Typography variant="body2">
                ✅ <strong>Host Status Visualization</strong> - Individual host progress with icons
              </Typography>
              <Typography variant="body2">
                ✅ <strong>Overall Progress Tracking</strong> - Session-level progress bar and
                statistics
              </Typography>
              <Typography variant="body2">
                ✅ <strong>Compliance Score Display</strong> - Results with color-coded scoring
              </Typography>
              <Typography variant="body2">
                ✅ <strong>Error Handling</strong> - Clear error messages and recovery options
              </Typography>
              <Typography variant="body2">
                ✅ <strong>Interactive Controls</strong> - Pause updates, cancel scans, view results
              </Typography>
              <Typography variant="body2">
                ✅ <strong>Notifications</strong> - Toast alerts for scan completion/failure
              </Typography>
              <Typography variant="body2">
                ✅ <strong>Authorization Awareness</strong> - Shows permission issues clearly
              </Typography>
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* Implementation Notes */}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Implementation Highlights
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={4}>
            <Typography variant="subtitle2" color="primary" gutterBottom>
              User Experience
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Immediate feedback when scanning starts, with clear visual indicators for each
              possible state (pending, running, completed, failed).
            </Typography>
          </Grid>
          <Grid item xs={12} sm={4}>
            <Typography variant="subtitle2" color="primary" gutterBottom>
              Real-time Updates
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Automatic polling with smart stop conditions, pause/resume controls, and background
              operation support.
            </Typography>
          </Grid>
          <Grid item xs={12} sm={4}>
            <Typography variant="subtitle2" color="primary" gutterBottom>
              Error Handling
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Comprehensive validation, graceful error recovery, and user-friendly error messages
              with actionable guidance.
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      {/* Demo Scan Progress Dialog */}
      <ScanProgressDialog
        open={showScanProgress}
        onClose={() => setShowScanProgress(false)}
        sessionId={mockSessionId}
        groupId={mockGroup.id}
        groupName={mockGroup.name}
        onCancel={() => {
          console.log('Demo: Cancelling scan');
          setShowScanProgress(false);
        }}
        onViewResults={(scanId) => {
          console.log('Demo: Viewing results for scan:', scanId);
          alert(`Demo: Would open results for scan ${scanId}`);
        }}
      />
    </Box>
  );
};

export default ScanProgressDemo;
