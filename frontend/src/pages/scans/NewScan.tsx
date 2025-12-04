import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Container, Typography, Box, Card, CardContent, Button, Alert } from '@mui/material';
import { ArrowBack, Scanner, Settings } from '@mui/icons-material';
import QuickScanDialog from '../../components/scans/QuickScanDialog';
import type { Host } from '../../types/host';

interface LocationState {
  hostId?: string;
  quickScan?: boolean;
  suggestedTemplate?: string;
}

const NewScan: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState;

  const [showQuickScanDialog, setShowQuickScanDialog] = useState(false);
  // Host data from API for quick scan display
  const [hostData, setHostData] = useState<Host | null>(null);

  useEffect(() => {
    // If coming from quick scan request, show quick scan dialog
    if (state?.quickScan && state?.hostId) {
      fetchHostData(state.hostId);
      setShowQuickScanDialog(true);
    }
  }, [state]);

  const fetchHostData = async (hostId: string) => {
    try {
      const response = await fetch(`/api/hosts/${hostId}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (response.ok) {
        const host = await response.json();
        setHostData(host);
      }
    } catch (error) {
      console.error('Failed to fetch host data:', error);
    }
  };

  const handleQuickScanStarted = (scanId: string) => {
    navigate(`/scans/${scanId}`);
  };

  const handleCloseQuickScan = () => {
    setShowQuickScanDialog(false);
    // Navigate back or to scans list
    navigate('/scans');
  };

  const handleFullWizard = () => {
    // Navigate to the unified scan wizard (ComplianceScanWizard)
    navigate('/scans/create', { state: { preselectedHostId: state?.hostId } });
  };

  // If in quick scan mode, render minimal UI
  if (state?.quickScan) {
    return (
      <>
        <Container maxWidth="md" sx={{ mt: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <Button startIcon={<ArrowBack />} onClick={() => navigate(-1)} sx={{ mr: 2 }}>
              Back
            </Button>
            <Typography variant="h4">Quick Scan</Typography>
          </Box>

          {state.hostId && hostData && (
            <Alert severity="info" sx={{ mb: 3 }}>
              Ready to scan <strong>{hostData.display_name || hostData.hostname}</strong> using
              optimized scan templates.
            </Alert>
          )}
        </Container>

        {showQuickScanDialog && hostData && (
          <QuickScanDialog
            open={showQuickScanDialog}
            onClose={handleCloseQuickScan}
            hostId={state.hostId!}
            hostName={hostData.display_name || hostData.hostname}
            onScanStarted={handleQuickScanStarted}
          />
        )}
      </>
    );
  }

  // Regular new scan page
  return (
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <Button startIcon={<ArrowBack />} onClick={() => navigate('/scans')} sx={{ mr: 2 }}>
          Back to Scans
        </Button>
        <Typography variant="h4">New Security Scan</Typography>
      </Box>

      <Box sx={{ mb: 4 }}>
        <Typography variant="body1" color="text.secondary">
          Choose how you want to configure your security scan
        </Typography>
      </Box>

      <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        {/* Quick Scan Option */}
        <Card sx={{ flex: 1, minWidth: 300 }}>
          <CardContent sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Scanner sx={{ fontSize: 32, color: 'primary.main', mr: 2 }} />
              <Typography variant="h6">Quick Scan</Typography>
            </Box>

            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Use pre-configured templates for fast, common scans like compliance checks and
              security audits. Perfect for routine scanning.
            </Typography>

            <Box sx={{ mb: 2 }}>
              <Typography variant="caption" color="text.secondary">
                ✓ Ready-to-use templates
                <br />
                ✓ 1-click scanning
                <br />
                ✓ 5-25 minute duration
                <br />✓ Most common use cases
              </Typography>
            </Box>

            <Button
              variant="contained"
              startIcon={<Scanner />}
              onClick={() => {
                if (state?.hostId) {
                  fetchHostData(state.hostId);
                  setShowQuickScanDialog(true);
                } else {
                  navigate('/hosts'); // Select host first
                }
              }}
              fullWidth
            >
              Start Quick Scan
            </Button>
          </CardContent>
        </Card>

        {/* Full Configuration Option */}
        <Card sx={{ flex: 1, minWidth: 300 }}>
          <CardContent sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Settings sx={{ fontSize: 32, color: 'info.main', mr: 2 }} />
              <Typography variant="h6">Advanced Configuration</Typography>
            </Box>

            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Full control over scan parameters including custom SCAP content, specific profiles,
              and detailed options. For specialized requirements.
            </Typography>

            <Box sx={{ mb: 2 }}>
              <Typography variant="caption" color="text.secondary">
                ✓ Custom SCAP content
                <br />
                ✓ Detailed configuration
                <br />
                ✓ Advanced options
                <br />✓ Specialized profiles
              </Typography>
            </Box>

            <Button
              variant="outlined"
              startIcon={<Settings />}
              onClick={handleFullWizard}
              fullWidth
            >
              Configure Advanced Scan
            </Button>
          </CardContent>
        </Card>
      </Box>

      {/* Quick Scan Dialog */}
      {showQuickScanDialog && hostData && (
        <QuickScanDialog
          open={showQuickScanDialog}
          onClose={handleCloseQuickScan}
          hostId={state?.hostId || ''}
          hostName={hostData.display_name || hostData.hostname}
          onScanStarted={handleQuickScanStarted}
        />
      )}
    </Container>
  );
};

export default NewScan;
