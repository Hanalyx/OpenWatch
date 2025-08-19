import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Container,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  LinearProgress,
  Menu,
  MenuItem,
  IconButton,
  Alert,
  Grid
} from '@mui/material';
import {
  Add as AddIcon,
  PlayArrow as PlayArrowIcon,
  MoreVert as MoreVertIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

interface Scan {
  id: string;
  name: string;
  host_name: string;
  content_name: string;
  profile_id: string;
  status: string;
  progress: number;
  started_at: string;
  completed_at?: string;
}

const Scans: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/scans/', {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setScans(data.scans || []);
      }
    } catch (error) {
      console.error('Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'running':
        return 'primary';
      case 'failed':
        return 'error';
      case 'pending':
        return 'warning';
      default:
        return 'default';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <Container maxWidth="xl">
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Compliance Scans
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Monitor and manage security compliance scans across your infrastructure
        </Typography>
      </Box>

      {/* Actions Bar */}
      <Box sx={{ mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={6}>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => navigate('/scans/new')}
              size="large"
            >
              New Scan
            </Button>
          </Grid>
          <Grid item xs={12} sm={6} sx={{ textAlign: 'right' }}>
            <Button
              variant="outlined"
              startIcon={<PlayArrowIcon />}
              onClick={() => console.log('Start all pending scans')}
              disabled={!scans.some(scan => scan.status === 'pending')}
            >
              Start All Pending
            </Button>
          </Grid>
        </Grid>
      </Box>

      {/* Scans Table */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Host</TableCell>
                <TableCell>Content</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Progress</TableCell>
                <TableCell>Started</TableCell>
                <TableCell>Completed</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={8}>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', py: 4 }}>
                      <LinearProgress sx={{ width: '100%' }} />
                    </Box>
                  </TableCell>
                </TableRow>
              ) : scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8}>
                    <Box sx={{ textAlign: 'center', py: 4 }}>
                      <Typography variant="body1" color="text.secondary" gutterBottom>
                        No scans found
                      </Typography>
                      <Button
                        variant="contained"
                        startIcon={<AddIcon />}
                        onClick={() => navigate('/scans/new')}
                      >
                        Create Your First Scan
                      </Button>
                    </Box>
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <TableRow key={scan.id} hover>
                    <TableCell>
                      <Typography variant="subtitle2" fontWeight="medium">
                        {scan.name}
                      </Typography>
                    </TableCell>
                    <TableCell>{scan.host_name}</TableCell>
                    <TableCell>{scan.content_name}</TableCell>
                    <TableCell>
                      <Chip
                        label={scan.status}
                        color={getStatusColor(scan.status)}
                        size="small"
                        variant="filled"
                      />
                    </TableCell>
                    <TableCell>
                      {scan.status === 'running' && (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={scan.progress}
                            sx={{ flexGrow: 1 }}
                          />
                          <Typography variant="caption">
                            {scan.progress}%
                          </Typography>
                        </Box>
                      )}
                    </TableCell>
                    <TableCell>{formatDate(scan.started_at)}</TableCell>
                    <TableCell>
                      {scan.completed_at ? formatDate(scan.completed_at) : '-'}
                    </TableCell>
                    <TableCell>
                      <IconButton size="small">
                        <MoreVertIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    </Container>
  );
};

export default Scans;