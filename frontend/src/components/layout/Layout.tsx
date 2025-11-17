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
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard,
  Computer,
  Group,
  FolderOpen,
  Scanner,
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
  OpenInNew,
  Launch,
  Download,
  ContentCopy,
  BookmarkAdd,
  AccountTree,
  Bookmark,
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
    roles: [
      'super_admin',
      'security_admin',
      'security_analyst',
      'compliance_officer',
      'auditor',
      'guest',
    ],
  },
  {
    text: 'Hosts',
    icon: <Computer />,
    path: '/hosts',
    roles: [
      'super_admin',
      'security_admin',
      'security_analyst',
      'compliance_officer',
      'auditor',
      'guest',
    ],
  },
  {
    text: 'Host Groups',
    icon: <Group />,
    path: '/host-groups',
    roles: ['super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor'],
  },
  {
    text: 'Content',
    icon: <FolderOpen />,
    path: '/content',
    roles: [
      'super_admin',
      'security_admin',
      'security_analyst',
      'compliance_officer',
      'auditor',
      'guest',
    ],
  },
  {
    text: 'Frameworks',
    icon: <AccountTree />,
    path: '/content/frameworks',
    roles: [
      'super_admin',
      'security_admin',
      'security_analyst',
      'compliance_officer',
      'auditor',
      'guest',
    ],
  },
  {
    text: 'Templates',
    icon: <Bookmark />,
    path: '/content/templates',
    roles: ['super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor'],
  },
  {
    text: 'Scans',
    icon: <Scanner />,
    path: '/scans',
    roles: ['super_admin', 'security_admin', 'security_analyst', 'compliance_officer', 'auditor'],
  },
  {
    text: 'Users',
    icon: <People />,
    path: '/users',
    roles: ['super_admin'],
  },
  {
    text: 'OView',
    icon: <Security />,
    path: '/oview',
    roles: ['super_admin', 'security_admin', 'compliance_officer', 'auditor'],
  },
  {
    text: 'Settings',
    icon: <Settings />,
    path: '/settings',
    roles: [
      'super_admin',
      'security_admin',
      'security_analyst',
      'compliance_officer',
      'auditor',
      'guest',
    ],
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
  const [drawerOpen, setDrawerOpen] = useState(false); // Desktop drawer state - collapsed by default
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  // Context menu state
  const [contextMenuAnchor, setContextMenuAnchor] = useState<{
    mouseX: number;
    mouseY: number;
  } | null>(null);
  const [contextMenuItem, setContextMenuItem] = useState<(typeof menuItems)[0] | null>(null);

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

  // Context menu handlers
  const handleContextMenu = (event: React.MouseEvent, item: (typeof menuItems)[0]) => {
    event.preventDefault();
    setContextMenuItem(item);
    setContextMenuAnchor({
      mouseX: event.clientX - 2,
      mouseY: event.clientY - 4,
    });
  };

  const handleContextMenuClose = () => {
    setContextMenuAnchor(null);
    setContextMenuItem(null);
  };

  const handleOpenInNewTab = () => {
    if (contextMenuItem) {
      const baseUrl = window.location.origin;
      const fullUrl = `${baseUrl}${contextMenuItem.path}`;
      window.open(fullUrl, '_blank');
    }
    handleContextMenuClose();
  };

  const handleOpenInNewWindow = () => {
    if (contextMenuItem) {
      const baseUrl = window.location.origin;
      const fullUrl = `${baseUrl}${contextMenuItem.path}`;
      window.open(fullUrl, '_blank', 'width=1200,height=800,scrollbars=yes,resizable=yes');
    }
    handleContextMenuClose();
  };

  const handleCopyLinkAddress = async () => {
    if (contextMenuItem) {
      const baseUrl = window.location.origin;
      const fullUrl = `${baseUrl}${contextMenuItem.path}`;

      try {
        await navigator.clipboard.writeText(fullUrl);
        // You could add a toast notification here for feedback
        console.log('Link copied to clipboard:', fullUrl);
      } catch {
        console.error('Failed to copy link to clipboard');
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = fullUrl;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }
    }
    handleContextMenuClose();
  };

  const handleSaveLinkAs = () => {
    if (contextMenuItem) {
      const baseUrl = window.location.origin;
      const fullUrl = `${baseUrl}${contextMenuItem.path}`;

      // Create a temporary anchor element to trigger download
      const link = document.createElement('a');
      link.href = fullUrl;
      link.download = `${contextMenuItem.text.toLowerCase().replace(/\s+/g, '-')}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
    handleContextMenuClose();
  };

  const handleBookmarkLink = () => {
    if (contextMenuItem) {
      const baseUrl = window.location.origin;
      const fullUrl = `${baseUrl}${contextMenuItem.path}`;

      // For modern browsers that support the Bookmarks API
      if ('external' in window && 'AddSearchProvider' in (window as any).external) {
        try {
          (window as any).external.AddFavorite(fullUrl, contextMenuItem.text);
        } catch {
          // Fallback: show instruction to user
          alert(
            `To bookmark this page, press Ctrl+D (or Cmd+D on Mac) when viewing: ${contextMenuItem.text}`
          );
        }
      } else {
        // Show instruction for manual bookmarking
        alert(
          `To bookmark this page, press Ctrl+D (or Cmd+D on Mac) when viewing: ${contextMenuItem.text}`
        );
      }
    }
    handleContextMenuClose();
  };

  const drawer = (
    <div>
      <Toolbar
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: drawerOpen ? 'space-between' : 'center',
          px: drawerOpen ? 3 : 1,
        }}
      >
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
              onContextMenu={(event) => handleContextMenu(event, item)}
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
        elevation={0}
        sx={{
          width: {
            sm: isMobile
              ? '100%'
              : `calc(100% - ${drawerOpen ? drawerWidth : collapsedDrawerWidth}px)`,
          },
          ml: {
            sm: isMobile ? 0 : `${drawerOpen ? drawerWidth : collapsedDrawerWidth}px`,
          },
          bgcolor: 'background.paper',
          color: 'text.primary',
          borderBottom: 1,
          borderColor: 'divider',
          transition: theme.transitions.create(['margin', 'width'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        <Toolbar>
          <IconButton
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { sm: 'none' }, color: 'text.primary' }}
          >
            <MenuIcon />
          </IconButton>
          <Typography
            variant="h6"
            noWrap
            component="div"
            sx={{ flexGrow: 1, color: 'text.primary' }}
          >
            {menuItems.find((item) => item.path === location.pathname)?.text || 'OpenWatch'}
          </Typography>

          <Tooltip title={`Switch to ${themeMode === 'light' ? 'dark' : 'light'} mode`}>
            <IconButton onClick={toggleTheme} sx={{ mr: 1, color: 'text.primary' }}>
              {themeMode === 'light' ? <DarkMode /> : <LightMode />}
            </IconButton>
          </Tooltip>

          <IconButton sx={{ mr: 1, color: 'text.primary' }}>
            <Badge badgeContent={notifications.length} color="error">
              <Notifications />
            </Badge>
          </IconButton>

          <IconButton onClick={handleProfileMenuOpen} sx={{ color: 'text.primary' }}>
            <Avatar
              sx={{ width: 32, height: 32, bgcolor: 'primary.main', color: 'primary.contrastText' }}
            >
              {user?.username.charAt(0).toUpperCase()}
            </Avatar>
          </IconButton>

          <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleProfileMenuClose}>
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

      {/* Navigation Context Menu */}
      <Menu
        open={contextMenuAnchor !== null}
        onClose={handleContextMenuClose}
        anchorReference="anchorPosition"
        anchorPosition={
          contextMenuAnchor !== null
            ? { top: contextMenuAnchor.mouseY, left: contextMenuAnchor.mouseX }
            : undefined
        }
        slotProps={{
          paper: {
            style: {
              maxHeight: 48 * 4.5,
              width: '20ch',
            },
          },
        }}
      >
        <MenuItem onClick={handleOpenInNewTab}>
          <OpenInNew sx={{ mr: 1 }} />
          Open link in new tab
        </MenuItem>
        <MenuItem onClick={handleOpenInNewWindow}>
          <Launch sx={{ mr: 1 }} />
          Open link in new window
        </MenuItem>
        <MenuItem onClick={handleSaveLinkAs}>
          <Download sx={{ mr: 1 }} />
          Save link as...
        </MenuItem>
        <MenuItem onClick={handleCopyLinkAddress}>
          <ContentCopy sx={{ mr: 1 }} />
          Copy link address
        </MenuItem>
        <MenuItem onClick={handleBookmarkLink}>
          <BookmarkAdd sx={{ mr: 1 }} />
          Bookmark link
        </MenuItem>
      </Menu>

      <Box
        component="nav"
        sx={{
          width: { sm: isMobile ? 0 : drawerOpen ? drawerWidth : collapsedDrawerWidth },
          flexShrink: { sm: 0 },
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
              width: isMobile ? drawerWidth : drawerOpen ? drawerWidth : collapsedDrawerWidth,
              transition: theme.transitions.create('width', {
                easing: theme.transitions.easing.sharp,
                duration: theme.transitions.duration.enteringScreen,
              }),
              overflowX: 'hidden',
              bgcolor: 'background.paper',
              borderRight: 1,
              borderColor: 'divider',
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
          maxWidth: '100vw',
          overflowX: 'hidden',
          minHeight: 'calc(100vh - 64px)',
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
