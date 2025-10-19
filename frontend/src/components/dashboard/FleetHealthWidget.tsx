import React from 'react';
import {
  Card,
  CardContent,
  Box,
  Typography,
  Chip,
  useTheme,
  alpha
} from '@mui/material';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { CheckCircle, Error, Warning, Schedule } from '@mui/icons-material';

interface FleetHealthData {
  online: number;
  degraded: number;
  critical: number;
  down: number;
  scanning: number;
  maintenance: number;
}

interface FleetHealthWidgetProps {
  data: FleetHealthData;
  groups?: Array<{
    name: string;
    color: string;
    count: number;
  }>;
  onSegmentClick?: (status: keyof FleetHealthData) => void;
}

const FleetHealthWidget: React.FC<FleetHealthWidgetProps> = ({
  data,
  groups,
  onSegmentClick
}) => {
  const theme = useTheme();

  // Ensure data integrity with all adaptive monitoring states
  const safeData = {
    online: Math.max(0, data?.online || 0),
    degraded: Math.max(0, data?.degraded || 0),
    critical: Math.max(0, data?.critical || 0),
    down: Math.max(0, data?.down || 0),
    scanning: Math.max(0, data?.scanning || 0),
    maintenance: Math.max(0, data?.maintenance || 0)
  };

  const chartData = [
    { name: 'Online', value: safeData.online, color: theme.palette.mode === 'dark' ? '#4caf50' : theme.palette.success.main },
    { name: 'Degraded', value: safeData.degraded, color: theme.palette.mode === 'dark' ? '#ff9800' : theme.palette.warning.main },
    { name: 'Critical', value: safeData.critical, color: theme.palette.mode === 'dark' ? '#f44336' : theme.palette.error.main },
    { name: 'Down', value: safeData.down, color: theme.palette.mode === 'dark' ? '#d32f2f' : theme.palette.error.dark },
    { name: 'Scanning', value: safeData.scanning, color: theme.palette.mode === 'dark' ? '#2196f3' : theme.palette.info.main },
    { name: 'Maintenance', value: safeData.maintenance, color: theme.palette.mode === 'dark' ? '#9e9e9e' : theme.palette.action.disabled }
  ].filter(item => item.value > 0);

  const totalHosts = safeData.online + safeData.degraded + safeData.critical + safeData.down + safeData.scanning + safeData.maintenance;

  const getIcon = (status: string) => {
    switch (status) {
      case 'Online': return <CheckCircle fontSize="small" />;
      case 'Degraded': return <Warning fontSize="small" />;
      case 'Critical': return <Error fontSize="small" />;
      case 'Down': return <Error fontSize="small" />;
      case 'Scanning': return <Schedule fontSize="small" />;
      case 'Maintenance': return <Warning fontSize="small" />;
      default: return null;
    }
  };

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0];
      return (
        <Box
          sx={{
            bgcolor: 'background.paper',
            p: 1.5,
            borderRadius: 1,
            boxShadow: theme.shadows[4],
            border: `1px solid ${theme.palette.divider}`
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box sx={{ color: data.payload.color }}>
              {getIcon(data.name)}
            </Box>
            <Typography variant="body2">
              {data.name}: <strong>{data.value}</strong>
            </Typography>
          </Box>
        </Box>
      );
    }
    return null;
  };

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Fleet Health Overview
        </Typography>
        
        <Box sx={{ 
          height: 200, 
          position: 'relative', 
          backgroundColor: theme.palette.mode === 'dark' ? alpha(theme.palette.background.paper, 0.8) : 'transparent',
          borderRadius: 1
        }}>
          {totalHosts > 0 ? (
            <ResponsiveContainer width="100%" height="100%" minHeight={200}>
              <PieChart width={400} height={200}>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={2}
                  dataKey="value"
                  onClick={(data) => {
                    if (onSegmentClick) {
                      const statusMap: { [key: string]: keyof FleetHealthData } = {
                        'Online': 'online',
                        'Offline': 'offline',
                        'Scanning': 'scanning',
                        'Maintenance': 'maintenance'
                      };
                      onSegmentClick(statusMap[data.name]);
                    }
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: 'text.secondary',
                textAlign: 'center'
              }}
            >
              <Box>
                <Typography variant="h6" gutterBottom>
                  No hosts registered
                </Typography>
                <Typography variant="body2">
                  Add hosts to see fleet health overview
                </Typography>
              </Box>
            </Box>
          )}
          
          {totalHosts > 0 && (
            <Box
              sx={{
                position: 'absolute',
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                textAlign: 'center'
              }}
            >
              <Typography variant="h4" fontWeight="bold">
                {totalHosts}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Total Hosts
              </Typography>
            </Box>
          )}
        </Box>

        <Box sx={{ mt: 2, display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {chartData.map((item) => (
            <Chip
              key={item.name}
              icon={getIcon(item.name) || undefined}
              label={`${item.name}: ${item.value}`}
              size="small"
              sx={{
                bgcolor: alpha(item.color, 0.1),
                color: item.color,
                '& .MuiChip-icon': {
                  color: item.color
                }
              }}
              onClick={() => {
                if (onSegmentClick) {
                  const statusMap: { [key: string]: keyof FleetHealthData } = {
                    'Online': 'online',
                    'Offline': 'offline',
                    'Scanning': 'scanning',
                    'Maintenance': 'maintenance'
                  };
                  onSegmentClick(statusMap[item.name]);
                }
              }}
            />
          ))}
        </Box>

        {groups && groups.length > 0 && (
          <>
            <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }} color="text.secondary">
              Host Groups
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
              {groups.map((group) => (
                <Chip
                  key={group.name}
                  label={`${group.name} (${group.count})`}
                  size="small"
                  sx={{
                    bgcolor: alpha(group.color, 0.1),
                    color: group.color,
                    borderColor: group.color,
                    fontSize: '0.75rem'
                  }}
                  variant="outlined"
                />
              ))}
            </Box>
          </>
        )}
      </CardContent>
    </Card>
  );
};

export default FleetHealthWidget;