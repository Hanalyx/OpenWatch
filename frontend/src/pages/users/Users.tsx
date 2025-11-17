import React, { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  Snackbar,
  Chip,
  Tooltip,
  TablePagination,
  InputAdornment,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Search as SearchIcon,
  Person as PersonIcon,
  AdminPanelSettings as AdminIcon,
  Security as SecurityIcon,
  Assessment as AnalystIcon,
  Policy as ComplianceIcon,
  Visibility as AuditorIcon,
  PersonOutline as GuestIcon,
} from '@mui/icons-material';
import { api } from '../../services/api';

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login?: string;
  failed_login_attempts: number;
  locked_until?: string;
}

interface Role {
  name: string;
  display_name: string;
  description: string;
  permissions: string[];
}

const roleIcons: Record<string, React.ReactElement> = {
  super_admin: <AdminIcon color="error" />,
  security_admin: <SecurityIcon color="warning" />,
  security_analyst: <AnalystIcon color="info" />,
  compliance_officer: <ComplianceIcon color="success" />,
  auditor: <AuditorIcon color="secondary" />,
  guest: <GuestIcon color="disabled" />,
};

const roleColors: Record<string, string> = {
  super_admin: '#f44336',
  security_admin: '#ff9800',
  security_analyst: '#2196f3',
  compliance_officer: '#4caf50',
  auditor: '#9c27b0',
  guest: '#757575',
};

const Users: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Dialog state
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);

  // Pagination and filtering
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Form state
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    role: 'guest',
    is_active: true,
  });

  const loadRoles = async () => {
    try {
      const response = await api.get('/api/users/roles');
      setRoles(response);
    } catch (err: any) {
      console.error('Error loading roles:', err);
    }
  };

  const loadUsers = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page: (page + 1).toString(),
        page_size: pageSize.toString(),
      });

      if (search) params.append('search', search);
      if (roleFilter) params.append('role', roleFilter);
      if (statusFilter !== '') params.append('is_active', statusFilter);

      const response = await api.get(`/api/users?${params.toString()}`);
      setUsers(response.users);
      setTotal(response.total);
    } catch (err: any) {
      setError('Failed to load users');
      console.error('Error loading users:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRoles();
  }, []);

  useEffect(() => {
    loadUsers();
  }, [page, pageSize, search, roleFilter, statusFilter]);

  const handleAddUser = () => {
    setEditingUser(null);
    setFormData({
      username: '',
      email: '',
      password: '',
      role: 'guest',
      is_active: true,
    });
    setDialogOpen(true);
  };

  const handleEditUser = (user: User) => {
    setEditingUser(user);
    setFormData({
      username: user.username,
      email: user.email,
      password: '',
      role: user.role,
      is_active: user.is_active,
    });
    setDialogOpen(true);
  };

  const handleDeleteUser = async (user: User) => {
    if (!confirm(`Are you sure you want to delete user "${user.username}"?`)) {
      return;
    }

    try {
      await api.delete(`/api/users/${user.id}`);
      setSuccess('User deleted successfully');
      loadUsers();
    } catch (err: any) {
      setError('Failed to delete user');
      console.error('Error deleting user:', err);
    }
  };

  const handleSaveUser = async () => {
    try {
      setLoading(true);

      if (editingUser) {
        // Update existing user
        const updateData: any = {};
        if (formData.username !== editingUser.username) updateData.username = formData.username;
        if (formData.email !== editingUser.email) updateData.email = formData.email;
        if (formData.role !== editingUser.role) updateData.role = formData.role;
        if (formData.is_active !== editingUser.is_active) updateData.is_active = formData.is_active;
        if (formData.password) updateData.password = formData.password;

        await api.put(`/api/users/${editingUser.id}`, updateData);
        setSuccess('User updated successfully');
      } else {
        // Create new user
        await api.post('/api/users', formData);
        setSuccess('User created successfully');
      }

      setDialogOpen(false);
      loadUsers();
    } catch (err: any) {
      setError(editingUser ? 'Failed to update user' : 'Failed to create user');
      console.error('Error saving user:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFormChange = (field: string, value: any) => {
    setFormData((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const getRoleDisplay = (role: string) => {
    const roleData = roles.find((r) => r.name === role);
    return roleData ? roleData.display_name : role;
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleString();
  };

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          <PersonIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          User Management
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Manage user accounts, roles, and permissions
        </Typography>
      </Box>

      {/* Filters and Actions */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            <TextField
              placeholder="Search users..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
              sx={{ minWidth: 200 }}
            />

            <FormControl sx={{ minWidth: 150 }}>
              <InputLabel>Role</InputLabel>
              <Select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                label="Role"
              >
                <MenuItem value="">All Roles</MenuItem>
                {roles.map((role) => (
                  <MenuItem key={role.name} value={role.name}>
                    {role.display_name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl sx={{ minWidth: 120 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                label="Status"
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="true">Active</MenuItem>
                <MenuItem value="false">Inactive</MenuItem>
              </Select>
            </FormControl>

            <Box sx={{ ml: 'auto' }}>
              <Button variant="contained" startIcon={<AddIcon />} onClick={handleAddUser}>
                Add User
              </Button>
            </Box>
          </Box>
        </CardContent>
      </Card>

      {/* Users Table */}
      <Card>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>User</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last Login</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {roleIcons[user.role] || <PersonIcon />}
                      <Box sx={{ ml: 2 }}>
                        <Typography variant="body2" fontWeight="medium">
                          {user.username}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {user.email}
                        </Typography>
                      </Box>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={getRoleDisplay(user.role)}
                      size="small"
                      sx={{
                        backgroundColor: `${roleColors[user.role]}20`,
                        color: roleColors[user.role],
                        fontWeight: 'medium',
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Box
                      sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}
                    >
                      <Chip
                        label={user.is_active ? 'Active' : 'Inactive'}
                        size="small"
                        color={user.is_active ? 'success' : 'error'}
                        variant="outlined"
                      />
                      {user.failed_login_attempts > 0 && (
                        <Typography variant="caption" color="warning.main" sx={{ mt: 0.5 }}>
                          {user.failed_login_attempts} failed attempts
                        </Typography>
                      )}
                      {user.locked_until && new Date(user.locked_until) > new Date() && (
                        <Typography variant="caption" color="error.main" sx={{ mt: 0.5 }}>
                          Locked until {formatDate(user.locked_until)}
                        </Typography>
                      )}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{formatDate(user.last_login)}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{formatDate(user.created_at)}</Typography>
                  </TableCell>
                  <TableCell>
                    <Tooltip title="Edit User">
                      <IconButton size="small" onClick={() => handleEditUser(user)} sx={{ mr: 1 }}>
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete User">
                      <IconButton size="small" onClick={() => handleDeleteUser(user)} color="error">
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
              {users.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary">No users found</Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>

        <TablePagination
          component="div"
          count={total}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          rowsPerPage={pageSize}
          onRowsPerPageChange={(e) => {
            setPageSize(parseInt(e.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[5, 10, 25, 50]}
        />
      </Card>

      {/* Add/Edit User Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{editingUser ? 'Edit User' : 'Add New User'}</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2, display: 'grid', gap: 2 }}>
            <TextField
              label="Username"
              fullWidth
              value={formData.username}
              onChange={(e) => handleFormChange('username', e.target.value)}
              required
            />

            <TextField
              label="Email"
              type="email"
              fullWidth
              value={formData.email}
              onChange={(e) => handleFormChange('email', e.target.value)}
              required
            />

            <TextField
              label="Password"
              type="password"
              fullWidth
              value={formData.password}
              onChange={(e) => handleFormChange('password', e.target.value)}
              helperText={
                editingUser ? 'Leave blank to keep current password' : 'Required for new users'
              }
              required={!editingUser}
            />

            <FormControl fullWidth>
              <InputLabel>Role</InputLabel>
              <Select
                value={formData.role}
                onChange={(e) => handleFormChange('role', e.target.value)}
                label="Role"
              >
                {roles.map((role) => (
                  <MenuItem key={role.name} value={role.name}>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {roleIcons[role.name]}
                      <Box sx={{ ml: 2 }}>
                        <Typography variant="body2">{role.display_name}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {role.description}
                        </Typography>
                      </Box>
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControlLabel
              control={
                <Switch
                  checked={formData.is_active}
                  onChange={(e) => handleFormChange('is_active', e.target.checked)}
                />
              }
              label="Active User"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleSaveUser}
            variant="contained"
            disabled={
              loading ||
              !formData.username ||
              !formData.email ||
              (!editingUser && !formData.password)
            }
          >
            {loading ? 'Saving...' : editingUser ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Success/Error Snackbars */}
      <Snackbar open={!!success} autoHideDuration={6000} onClose={() => setSuccess(null)}>
        <Alert onClose={() => setSuccess(null)} severity="success">
          {success}
        </Alert>
      </Snackbar>

      <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError(null)}>
        <Alert onClose={() => setError(null)} severity="error">
          {error}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Users;
