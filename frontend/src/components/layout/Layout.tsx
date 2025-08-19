import React, { useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Divider,
  Avatar,
  Menu,
  MenuItem,
  Badge,
  useTheme,
  useMediaQuery,
  Tooltip,
  styled,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard,
  Computer,
  FolderOpen,
  Scanner,
  Assessment,
  People,
  Security,
  Settings,
  Logout,
  AccountCircle,
  Notifications,
  ChevronLeft,
  ChevronRight,
  DarkMode,
  LightMode,
  CloudSync,
  Psychology,
} from '@mui/icons-material';
import { useAppDispatch, useAppSelector } from '../../hooks/redux';
import { logout } from '../../store/slices/authSlice';
import { useTheme as useCustomTheme } from '../../contexts/ThemeContext';

const drawerWidth = 240;
const collapsedDrawerWidth = 64;

const menuItems = [
  { 
    text: 'Dashboard', 
    icon: <Dashboard />, 
    path: '/', 
    roles: ['super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor', 'guest'] 
  },
  { 
    text: 'Hosts', 
    icon: <Computer />, 
    path: '/hosts', 
    roles: ['super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor', 'guest'] 
  },
  { 
    text: 'Content', 
    icon: <FolderOpen />, 
    path: '/content', 
    roles: ['super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor', 'guest'] 
  },
  { 
    text: 'Scans', 
    icon: <Scanner />, 
    path: '/scans', 
    roles: ['super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor'] 
  },
  { 
    text: 'Users', 
    icon: <People />, 
    path: '/users', 
    roles: ['super_admin'] 
  },
  { 
    text: 'OView', 
    icon: <Security />, 
    path: '/oview', 
    roles: ['super_admin', 'security_admin', 'compliance_officer', 'auditor'] 
  },
  { 
    text: 'Settings', 
    icon: <Settings />, 
    path: '/settings', 
    roles: ['super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor', 'guest'] 
  },
];

const Layout: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useAppDispatch();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const { user } = useAppSelector((state) => state.auth);
  const notifications = useAppSelector((state) => state.notifications.notifications);
  const { mode: themeMode, toggleTheme } = useCustomTheme();

  const [mobileOpen, setMobileOpen] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(true); // Desktop drawer state
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const handleDrawerToggle = () => {
    if (isMobile) {
      setMobileOpen(!mobileOpen);
    } else {
      setDrawerOpen(!drawerOpen);
    }
  };

  const handleMenuClick = (path: string) => {
    navigate(path);
    if (isMobile) {
      setMobileOpen(false);
    }
  };

  const handleProfileMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleProfileMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = async () => {
    await dispatch(logout());
    navigate('/login');
  };

  const drawer = (
    <div>
      <Toolbar sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: drawerOpen ? 'space-between' : 'center',
        px: drawerOpen ? 3 : 1 
      }}>
        {drawerOpen ? (
          <>
            <Typography variant="h6" noWrap sx={{ fontWeight: 'bold' }}>
              OpenWatch
            </Typography>
            {!isMobile && (
              <IconButton onClick={handleDrawerToggle} size="small">
                <ChevronLeft />
              </IconButton>
            )}
          </>
        ) : (
          !isMobile && (
            <IconButton onClick={handleDrawerToggle} size="small">
              <ChevronRight />
            </IconButton>
          )
        )}
      </Toolbar>
      <Divider />
      <List>
        {menuItems.map((item) => {
          const isSelected = location.pathname === item.path;
          const userRole = user?.role || 'guest';
          
          // Check if user has access to this menu item
          if (!item.roles.includes(userRole)) {
            return null;
          }

          const listItemButton = (
            <ListItemButton
              selected={isSelected}
              onClick={() => handleMenuClick(item.path)}
              sx={{
                minHeight: 48,
                justifyContent: drawerOpen ? 'initial' : 'center',
                px: 2.5,
              }}
            >
              <ListItemIcon
                sx={{
                  minWidth: 0,
                  mr: drawerOpen ? 3 : 'auto',
                  justifyContent: 'center',
                  color: isSelected ? 'primary.main' : 'inherit',
                }}
              >
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.text}
                sx={{ opacity: drawerOpen ? 1 : 0 }}
                primaryTypographyProps={{
                  fontWeight: isSelected ? 'medium' : 'normal',
                }}
              />
            </ListItemButton>
          );

          return (
            <ListItem key={item.text} disablePadding sx={{ display: 'block' }}>
              {!drawerOpen ? (
                <Tooltip title={item.text} placement="right">
                  {listItemButton}
                </Tooltip>
              ) : (
                listItemButton
              )}
            </ListItem>
          );
        })}
      </List>
    </div>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          width: { 
            sm: isMobile ? '100%' : `calc(100% - ${drawerOpen ? drawerWidth : collapsedDrawerWidth}px)` 
          },
          ml: { 
            sm: isMobile ? 0 : `${drawerOpen ? drawerWidth : collapsedDrawerWidth}px` 
          },
          transition: theme.transitions.create(['margin', 'width'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { sm: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            {menuItems.find((item) => item.path === location.pathname)?.text || 'OpenWatch'}
          </Typography>
          
          <Tooltip title={`Switch to ${themeMode === 'light' ? 'dark' : 'light'} mode`}>
            <IconButton color="inherit" onClick={toggleTheme} sx={{ mr: 1 }}>
              {themeMode === 'light' ? <DarkMode /> : <LightMode />}
            </IconButton>
          </Tooltip>
          
          <IconButton color="inherit" sx={{ mr: 1 }}>
            <Badge badgeContent={notifications.length} color="error">
              <Notifications />
            </Badge>
          </IconButton>
          
          <IconButton onClick={handleProfileMenuOpen} color="inherit">
            <Avatar sx={{ width: 32, height: 32 }}>
              {user?.username.charAt(0).toUpperCase()}
            </Avatar>
          </IconButton>
          
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={handleProfileMenuClose}
          >
            <MenuItem disabled>
              <AccountCircle sx={{ mr: 1 }} />
              {user?.username}
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => navigate('/settings')}>
              <Settings sx={{ mr: 1 }} />
              Settings
            </MenuItem>
            <MenuItem onClick={handleLogout}>
              <Logout sx={{ mr: 1 }} />
              Logout
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>
      
      <Box
        component="nav"
        sx={{ 
          width: { sm: isMobile ? 0 : (drawerOpen ? drawerWidth : collapsedDrawerWidth) }, 
          flexShrink: { sm: 0 } 
        }}
      >
        <Drawer
          variant={isMobile ? 'temporary' : 'permanent'}
          open={isMobile ? mobileOpen : true}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true,
          }}
          sx={{
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: isMobile ? drawerWidth : (drawerOpen ? drawerWidth : collapsedDrawerWidth),
              transition: theme.transitions.create('width', {
                easing: theme.transitions.easing.sharp,
                duration: theme.transitions.duration.enteringScreen,
              }),
              overflowX: 'hidden',
            },
          }}
        >
          {drawer}
        </Drawer>
      </Box>
      
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          transition: theme.transitions.create(['margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        <Toolbar />
        <Outlet />
      </Box>
    </Box>
  );
};

export default Layout;