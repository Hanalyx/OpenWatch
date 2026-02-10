/**
 * Services Tab
 *
 * Displays system services with status filtering and search.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/ServicesTab
 */

import React, { useState } from 'react';
import {
  Box,
  TextField,
  InputAdornment,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Paper,
  Typography,
  Chip,
  Alert,
  CircularProgress,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material';
import { Search as SearchIcon } from '@mui/icons-material';
import { useServices } from '../../../../hooks/useHostDetail';

interface ServicesTabProps {
  hostId: string;
}

type StatusFilter = 'all' | 'running' | 'stopped' | 'failed';

/**
 * Get color for service status chip
 */
function getStatusColor(status: string | null): 'success' | 'error' | 'warning' | 'default' {
  switch (status) {
    case 'running':
      return 'success';
    case 'stopped':
      return 'default';
    case 'failed':
      return 'error';
    default:
      return 'warning';
  }
}

const ServicesTab: React.FC<ServicesTabProps> = ({ hostId }) => {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const { data, isLoading, error } = useServices(hostId, {
    search: search || undefined,
    status: statusFilter !== 'all' ? statusFilter : undefined,
    limit: rowsPerPage,
    offset: page * rowsPerPage,
  });

  const handleChangePage = (_event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(event.target.value);
    setPage(0);
  };

  const handleStatusFilterChange = (
    _event: React.MouseEvent<HTMLElement>,
    newFilter: StatusFilter | null
  ) => {
    if (newFilter !== null) {
      setStatusFilter(newFilter);
      setPage(0);
    }
  };

  if (isLoading && !data) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load services: {error instanceof Error ? error.message : 'Unknown error'}
      </Alert>
    );
  }

  if (!data || data.total === 0) {
    return (
      <Alert severity="info">
        No service data available. Service information will be collected during the next scan.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Filters */}
      <Box sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
        <TextField
          size="small"
          placeholder="Search services..."
          value={search}
          onChange={handleSearchChange}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          }}
          sx={{ width: 300 }}
        />

        <ToggleButtonGroup
          value={statusFilter}
          exclusive
          onChange={handleStatusFilterChange}
          size="small"
        >
          <ToggleButton value="all">All</ToggleButton>
          <ToggleButton value="running">Running</ToggleButton>
          <ToggleButton value="stopped">Stopped</ToggleButton>
          <ToggleButton value="failed">Failed</ToggleButton>
        </ToggleButtonGroup>

        <Typography variant="body2" color="text.secondary">
          {data.total} services
        </Typography>
      </Box>

      {/* Table */}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Service Name</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Enabled</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>User</TableCell>
              <TableCell>Listening Ports</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.items.map((service, idx) => (
              <TableRow key={`${service.name}-${idx}`} hover>
                <TableCell>
                  <Box>
                    <Typography variant="body2" fontWeight="medium">
                      {service.name}
                    </Typography>
                    {service.displayName && service.displayName !== service.name && (
                      <Typography variant="caption" color="text.secondary">
                        {service.displayName}
                      </Typography>
                    )}
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={service.status || 'unknown'}
                    color={getStatusColor(service.status)}
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2">
                    {service.enabled === true ? 'Yes' : service.enabled === false ? 'No' : '-'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">{service.serviceType || '-'}</Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {service.runAsUser || '-'}
                  </Typography>
                </TableCell>
                <TableCell>
                  {service.listeningPorts && service.listeningPorts.length > 0 ? (
                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                      {service.listeningPorts.slice(0, 3).map((port, portIdx) => (
                        <Chip
                          key={portIdx}
                          size="small"
                          variant="outlined"
                          label={`${port.port}/${port.protocol}`}
                        />
                      ))}
                      {service.listeningPorts.length > 3 && (
                        <Chip
                          size="small"
                          variant="outlined"
                          label={`+${service.listeningPorts.length - 3}`}
                        />
                      )}
                    </Box>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      -
                    </Typography>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Pagination */}
      <TablePagination
        component="div"
        count={data.total}
        page={page}
        onPageChange={handleChangePage}
        rowsPerPage={rowsPerPage}
        onRowsPerPageChange={handleChangeRowsPerPage}
        rowsPerPageOptions={[10, 25, 50, 100]}
      />
    </Box>
  );
};

export default ServicesTab;
