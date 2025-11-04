import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Box,
  Typography,
  Button,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Alert,
  Skeleton,
  LinearProgress,
  Tooltip,
} from '@mui/material';
import {
  AutoAwesome,
  CheckCircle,
  Schedule,
  Computer,
  Security,
  TrendingUp,
  PlayArrow,
  Info,
  Warning,
  Psychology,
} from '@mui/icons-material';

interface ScanRecommendation {
  profile_id: string;
  content_id: number;
  name: string;
  confidence: number;
  reasoning: string[];
  estimated_duration: string;
  rule_count: number;
  priority: string;
}

interface HostRecommendation {
  host_id: string;
  hostname: string;
  display_name?: string;
  operating_system?: string;
  environment?: string;
  last_scan?: string;
  compliance_score?: number;
  recommendation: ScanRecommendation;
  risk_factors?: string[];
}

interface ScanRecommendationCardProps {
  hostId: string;
  onScanStart?: (hostId: string, recommendation: ScanRecommendation) => void;
}

const ScanRecommendationCard: React.FC<ScanRecommendationCardProps> = ({ hostId, onScanStart }) => {
  const [recommendation, setRecommendation] = useState<HostRecommendation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadRecommendation();
  }, [hostId]);

  const loadRecommendation = async () => {
    try {
      setLoading(true);
      setError(null);

      // In a real implementation, this would call the intelligence service
      // const response = await fetch(`/api/scans/hosts/${hostId}/recommendation`, {
      //   headers: { 'Authorization': `Bearer ${localStorage.getItem('auth_token')}` }
      // });

      // Mock recommendation for demo
      await new Promise((resolve) => setTimeout(resolve, 1000)); // Simulate API call

      const mockRecommendation: HostRecommendation = {
        host_id: hostId,
        hostname: 'web-server-01',
        display_name: 'Production Web Server 01',
        operating_system: 'RHEL 8.5',
        environment: 'production',
        last_scan: '2024-08-20T10:30:00Z',
        compliance_score: 78,
        recommendation: {
          profile_id: 'xccdf_org.ssgproject.content_profile_cui',
          content_id: 1,
          name: 'CUI Compliance Scan',
          confidence: 0.92,
          reasoning: [
            'Production environment detected',
            'Previous compliance score below 80%',
            'RHEL 8 system optimized for CUI profile',
            'Web server tag indicates public-facing service',
          ],
          estimated_duration: '12-15 min',
          rule_count: 185,
          priority: 'high',
        },
        risk_factors: [
          'Compliance score below target (78% < 85%)',
          'Last scan over 7 days ago',
          'Public-facing web server',
        ],
      };

      setRecommendation(mockRecommendation);
    } catch (err: any) {
      setError(err.message || 'Failed to load recommendation');
    } finally {
      setLoading(false);
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'success';
    if (confidence >= 0.6) return 'warning';
    return 'error';
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      default:
        return 'info';
    }
  };

  const formatLastScan = (lastScan?: string) => {
    if (!lastScan) return 'Never scanned';

    const date = new Date(lastScan);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    return `${Math.floor(diffDays / 30)} months ago`;
  };

  const handleStartScan = () => {
    if (recommendation && onScanStart) {
      onScanStart(recommendation.host_id, recommendation.recommendation);
    }
  };

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <Psychology color="primary" />
            <Skeleton variant="text" width={200} height={28} />
          </Box>
          <Skeleton variant="rectangular" width="100%" height={100} sx={{ mb: 2 }} />
          <Skeleton variant="text" width="100%" height={20} />
          <Skeleton variant="text" width="80%" height={20} />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <Alert severity="error" onClose={() => setError(null)}>
            {error}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (!recommendation) {
    return null;
  }

  const { recommendation: scanRec, risk_factors } = recommendation;

  return (
    <Card sx={{ border: '2px solid', borderColor: 'primary.light' }}>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Psychology color="primary" />
            <Typography variant="h6" fontWeight="bold">
              AI Scan Recommendation
            </Typography>
          </Box>
          <Chip
            icon={<AutoAwesome />}
            label={`${Math.round(scanRec.confidence * 100)}% Confidence`}
            color={getConfidenceColor(scanRec.confidence) as any}
            variant="outlined"
          />
        </Box>

        {/* Host Info */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <Computer color="action" />
          <Box>
            <Typography variant="body1" fontWeight="medium">
              {recommendation.display_name || recommendation.hostname}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {recommendation.operating_system} • {recommendation.environment}
            </Typography>
          </Box>
        </Box>

        {/* Recommended Scan */}
        <Alert
          severity="info"
          icon={<Security />}
          sx={{ mb: 2 }}
          action={
            <Button
              variant="contained"
              size="small"
              startIcon={<PlayArrow />}
              onClick={handleStartScan}
            >
              Start Scan
            </Button>
          }
        >
          <Typography variant="subtitle2" fontWeight="bold">
            {scanRec.name}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
            <Chip
              icon={<Schedule />}
              label={scanRec.estimated_duration}
              size="small"
              variant="outlined"
            />
            <Chip label={`${scanRec.rule_count} rules`} size="small" variant="outlined" />
            <Chip
              label={scanRec.priority.toUpperCase()}
              size="small"
              color={getPriorityColor(scanRec.priority) as any}
              variant="outlined"
            />
          </Box>
        </Alert>

        {/* Current Status */}
        <Box sx={{ mb: 2 }}>
          <Typography variant="subtitle2" gutterBottom>
            Current Status
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Typography variant="body2" color="text.secondary">
                Last Scan:
              </Typography>
              <Typography variant="body2">{formatLastScan(recommendation.last_scan)}</Typography>
            </Box>
            {recommendation.compliance_score !== undefined && (
              <>
                <Divider orientation="vertical" flexItem />
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Typography variant="body2" color="text.secondary">
                    Score:
                  </Typography>
                  <Typography
                    variant="body2"
                    color={recommendation.compliance_score >= 85 ? 'success.main' : 'warning.main'}
                    fontWeight="medium"
                  >
                    {recommendation.compliance_score}%
                  </Typography>
                </Box>
              </>
            )}
          </Box>

          {recommendation.compliance_score !== undefined && (
            <Box sx={{ mt: 1 }}>
              <LinearProgress
                variant="determinate"
                value={recommendation.compliance_score}
                sx={{ height: 6, borderRadius: 3 }}
                color={recommendation.compliance_score >= 85 ? 'success' : 'warning'}
              />
            </Box>
          )}
        </Box>

        {/* Risk Factors */}
        {risk_factors && risk_factors.length > 0 && (
          <Box sx={{ mb: 2 }}>
            <Typography
              variant="subtitle2"
              gutterBottom
              sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
            >
              <Warning color="warning" fontSize="small" />
              Risk Factors
            </Typography>
            <List dense sx={{ py: 0 }}>
              {risk_factors.map((factor, index) => (
                <ListItem key={index} sx={{ py: 0.5 }}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <Warning fontSize="small" color="warning" />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Typography variant="body2" color="text.secondary">
                        {factor}
                      </Typography>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        )}

        {/* AI Reasoning */}
        <Box>
          <Typography
            variant="subtitle2"
            gutterBottom
            sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
          >
            <Psychology color="primary" fontSize="small" />
            AI Analysis
          </Typography>
          <List dense sx={{ py: 0 }}>
            {scanRec.reasoning.map((reason, index) => (
              <ListItem key={index} sx={{ py: 0.25 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircle fontSize="small" color="success" />
                </ListItemIcon>
                <ListItemText primary={<Typography variant="body2">{reason}</Typography>} />
              </ListItem>
            ))}
          </List>
        </Box>

        {/* Action Buttons */}
        <Box sx={{ mt: 2, display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
          <Tooltip title="Learn more about this recommendation">
            <Button variant="outlined" size="small" startIcon={<Info />}>
              Details
            </Button>
          </Tooltip>
          <Button
            variant="contained"
            size="small"
            startIcon={<PlayArrow />}
            onClick={handleStartScan}
          >
            Start Recommended Scan
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};

export default ScanRecommendationCard;
