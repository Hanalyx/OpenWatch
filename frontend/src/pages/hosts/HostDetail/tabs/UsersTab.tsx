/**
 * Users Tab
 *
 * Displays user accounts with sudo filtering and search.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/UsersTab
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
  FormControlLabel,
  Switch,
  Tooltip,
} from '@mui/material';
import { Search as SearchIcon, Warning as WarningIcon } from '@mui/icons-material';
import { useUsers } from '../../../../hooks/useHostDetail';

interface UsersTabProps {
  hostId: string;
}

const UsersTab: React.FC<UsersTabProps> = ({ hostId }) => {
  const [search, setSearch] = useState('');
  const [showSystemUsers, setShowSystemUsers] = useState(false);
  const [sudoOnly, setSudoOnly] = useState(false);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const { data, isLoading, error } = useUsers(hostId, {
    search: search || undefined,
    includeSystem: showSystemUsers,
    hasSudo: sudoOnly || undefined,
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
        Failed to load users: {error instanceof Error ? error.message : 'Unknown error'}
      </Alert>
    );
  }

  if (!data || data.total === 0) {
    return (
      <Alert severity="info">
        No user data available. User information will be collected during the next scan.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Filters */}
      <Box sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
        <TextField
          size="small"
          placeholder="Search users..."
          value={search}
          onChange={handleSearchChange}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          }}
          sx={{ width: 250 }}
        />

        <FormControlLabel
          control={
            <Switch
              checked={showSystemUsers}
              onChange={(e) => {
                setShowSystemUsers(e.target.checked);
                setPage(0);
              }}
              size="small"
            />
          }
          label="Show system accounts"
        />

        <FormControlLabel
          control={
            <Switch
              checked={sudoOnly}
              onChange={(e) => {
                setSudoOnly(e.target.checked);
                setPage(0);
              }}
              size="small"
            />
          }
          label="Sudo users only"
        />

        <Typography variant="body2" color="text.secondary">
          {data.total} users
        </Typography>
      </Box>

      {/* Table */}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Username</TableCell>
              <TableCell>UID</TableCell>
              <TableCell>Groups</TableCell>
              <TableCell>Shell</TableCell>
              <TableCell>Sudo</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Last Login</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.items.map((user, idx) => (
              <TableRow key={`${user.username}-${idx}`} hover>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="body2" fontWeight="medium">
                      {user.username}
                    </Typography>
                    {user.isSystemAccount && (
                      <Chip size="small" label="system" variant="outlined" />
                    )}
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {user.uid ?? '-'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography
                    variant="body2"
                    sx={{
                      maxWidth: 200,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {user.groups?.join(', ') || '-'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {user.shell || '-'}
                  </Typography>
                </TableCell>
                <TableCell>
                  {user.hasSudoAll ||
                  user.hasSudoNopasswd ||
                  (user.sudoRules && user.sudoRules.length > 0) ? (
                    <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                      {user.hasSudoAll && (
                        <Tooltip title="Full sudo access (ALL)">
                          <Chip size="small" color="warning" label="ALL" />
                        </Tooltip>
                      )}
                      {user.hasSudoNopasswd && (
                        <Tooltip title="No password required for sudo">
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <WarningIcon color="error" fontSize="small" />
                            <Chip size="small" color="error" label="NOPASSWD" />
                          </Box>
                        </Tooltip>
                      )}
                      {!user.hasSudoAll && !user.hasSudoNopasswd && user.sudoRules && (
                        <Chip size="small" variant="outlined" label="Limited" />
                      )}
                    </Box>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      -
                    </Typography>
                  )}
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 0.5 }}>
                    {user.isLocked && <Chip size="small" color="error" label="Locked" />}
                    {user.hasPassword === false && (
                      <Chip size="small" variant="outlined" label="No password" />
                    )}
                    {user.sshKeysCount !== null && user.sshKeysCount > 0 && (
                      <Chip
                        size="small"
                        variant="outlined"
                        label={`${user.sshKeysCount} SSH keys`}
                      />
                    )}
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {user.lastLogin ? new Date(user.lastLogin).toLocaleDateString() : 'Never'}
                  </Typography>
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

export default UsersTab;
