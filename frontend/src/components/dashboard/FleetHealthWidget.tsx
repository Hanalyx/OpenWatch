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
  offline: number;
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

  const chartData = [
    { name: 'Online', value: data.online, color: theme.palette.success.main },
    { name: 'Offline', value: data.offline, color: theme.palette.error.main },
    { name: 'Scanning', value: data.scanning, color: theme.palette.info.main },
    { name: 'Maintenance', value: data.maintenance, color: theme.palette.warning.main }
  ].filter(item => item.value > 0);

  const totalHosts = data.online + data.offline + data.scanning + data.maintenance;

  const getIcon = (status: string) => {
    switch (status) {
      case 'Online': return <CheckCircle fontSize="small" />;
      case 'Offline': return <Error fontSize="small" />;
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
        
        <Box sx={{ height: 200, position: 'relative' }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
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