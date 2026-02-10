/**
 * Packages Tab
 *
 * Displays installed packages with search and pagination.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/PackagesTab
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
  Alert,
  CircularProgress,
} from '@mui/material';
import { Search as SearchIcon } from '@mui/icons-material';
import { usePackages } from '../../../../hooks/useHostDetail';

interface PackagesTabProps {
  hostId: string;
}

const PackagesTab: React.FC<PackagesTabProps> = ({ hostId }) => {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const { data, isLoading, error } = usePackages(hostId, {
    search: search || undefined,
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
    setPage(0); // Reset to first page on search
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
        Failed to load packages: {error instanceof Error ? error.message : 'Unknown error'}
      </Alert>
    );
  }

  if (!data || data.total === 0) {
    return (
      <Alert severity="info">
        No package data available. Package information will be collected during the next scan.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Search */}
      <Box sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 2 }}>
        <TextField
          size="small"
          placeholder="Search packages..."
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
        <Typography variant="body2" color="text.secondary">
          {data.total} packages total
        </Typography>
      </Box>

      {/* Table */}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Package Name</TableCell>
              <TableCell>Version</TableCell>
              <TableCell>Release</TableCell>
              <TableCell>Architecture</TableCell>
              <TableCell>Repository</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.items.map((pkg, idx) => (
              <TableRow key={`${pkg.name}-${idx}`} hover>
                <TableCell>
                  <Typography variant="body2" fontWeight="medium">
                    {pkg.name}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {pkg.version || '-'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {pkg.release || '-'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">{pkg.arch || '-'}</Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {pkg.sourceRepo || '-'}
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

export default PackagesTab;
