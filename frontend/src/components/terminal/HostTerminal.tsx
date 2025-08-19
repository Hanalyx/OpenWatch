import React, { useEffect, useRef, useState } from 'react';
import { Box, Alert, Button, Typography, CircularProgress, Chip } from '@mui/material';
import { Terminal } from '@xterm/xterm';
import { AttachAddon } from '@xterm/addon-attach';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { 
  Terminal as TerminalIcon, 
  Refresh as RefreshIcon, 
  Close as CloseIcon 
} from '@mui/icons-material';

interface HostTerminalProps {
  hostId: string;
  hostname: string;
  ipAddress: string;
}

interface ConnectionStatus {
  status: 'disconnected' | 'connecting' | 'connected' | 'failed' | 'closed';
  message?: string;
}

const HostTerminal: React.FC<HostTerminalProps> = ({ hostId, hostname, ipAddress }) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const websocket = useRef<WebSocket | null>(null);
  const attachAddon = useRef<AttachAddon | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>({ 
    status: 'disconnected' 
  });
  const [isInitialized, setIsInitialized] = useState(false);

  // Initialize terminal
  useEffect(() => {
    if (!terminalRef.current || isInitialized) return;

    // Delay terminal initialization to ensure DOM is ready
    const initTerminal = () => {
      try {
        // Create terminal instance
        terminal.current = new Terminal({
          cursorBlink: true,
          fontSize: 14,
          fontFamily: 'Monaco, Menlo, "Ubuntu Mono", monospace',
          theme: {
            background: '#1a1a1a',
            foreground: '#ffffff',
            cursor: '#ffffff',
            cursorAccent: '#000000',
            selectionBackground: 'rgba(255, 255, 255, 0.3)',
          },
          cols: 80,
          rows: 24,
        });

        // Add addons
        fitAddon.current = new FitAddon();
        terminal.current.loadAddon(fitAddon.current);
        terminal.current.loadAddon(new WebLinksAddon());

        // Open terminal
        if (terminalRef.current) {
          terminal.current.open(terminalRef.current);
        }
        
        // Fit terminal after a small delay to ensure DOM is rendered
        setTimeout(() => {
          if (fitAddon.current) {
            fitAddon.current.fit();
          }
          // Enable auto-scroll to bottom and focus
          if (terminal.current) {
            // Scroll to the bottom using buffer position
            terminal.current.scrollToLine(terminal.current.buffer.active.length);
            terminal.current.focus();
          }
        }, 100);

        // Welcome message
        terminal.current.writeln('\x1b[1;36mOpenWatch Terminal\x1b[0m');
        terminal.current.writeln(`Host: ${hostname} (${ipAddress})`);
        terminal.current.writeln('Click "Connect" to establish SSH connection...\r\n');

        setIsInitialized(true);

        // Handle resize
        const handleResize = () => {
          if (fitAddon.current && terminal.current) {
            try {
              fitAddon.current.fit();
            } catch (error) {
              console.warn('Terminal resize error:', error);
            }
          }
        };
        window.addEventListener('resize', handleResize);

        return () => {
          window.removeEventListener('resize', handleResize);
          
          if (terminal.current) {
            terminal.current.dispose();
          }
          if (websocket.current) {
            websocket.current.close();
          }
        };
      } catch (error) {
        console.error('Terminal initialization error:', error);
      }
    };

    // Small delay to ensure the container is properly sized
    const timeoutId = setTimeout(initTerminal, 50);
    
    return () => {
      clearTimeout(timeoutId);
    };
  }, [hostname, ipAddress, isInitialized]);

  const connect = () => {
    if (!terminal.current) return;

    setConnectionStatus({ status: 'connecting', message: 'Establishing connection...' });
    
    // Create WebSocket connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/hosts/${hostId}/terminal`;
    
    websocket.current = new WebSocket(wsUrl);

    websocket.current.onopen = () => {
      setConnectionStatus({ status: 'connected', message: 'Connected successfully' });
      
      if (terminal.current && websocket.current) {
        // Attach WebSocket to terminal
        attachAddon.current = new AttachAddon(websocket.current);
        terminal.current.loadAddon(attachAddon.current);
        
        // Clear terminal and show connection message
        terminal.current.clear();
        terminal.current.writeln('\x1b[1;32m✓ SSH Connection Established\x1b[0m');
        terminal.current.writeln(`Connected to ${hostname} (${ipAddress})\r\n`);
        
        // Focus terminal and scroll to bottom
        terminal.current.focus();
        
        // Robust auto-scroll implementation that follows cursor
        const ensureCursorVisible = () => {
          if (terminal.current) {
            const buffer = terminal.current.buffer.active;
            const cursorLine = buffer.baseY + buffer.cursorY;
            const viewportBottom = buffer.viewportY + terminal.current.rows;
            
            // If cursor is below viewport, scroll to show it
            if (cursorLine >= viewportBottom) {
              terminal.current.scrollToLine(cursorLine - terminal.current.rows + 1);
            }
            // Always scroll to bottom to ensure latest content is visible
            terminal.current.scrollToBottom();
          }
        };
        
        // Set up auto-scroll on any terminal activity
        const scrollHandler = () => {
          // Small delay to let terminal process the data first
          setTimeout(ensureCursorVisible, 20);
        };
        
        terminal.current.onWriteParsed(scrollHandler);
        terminal.current.onData(scrollHandler);
        
        // Initial scroll to bottom
        setTimeout(ensureCursorVisible, 100);
      }
    };

    websocket.current.onclose = (event) => {
      setConnectionStatus({ 
        status: 'closed', 
        message: event.wasClean ? 'Connection closed' : 'Connection lost' 
      });
      
      if (terminal.current) {
        terminal.current.writeln('\r\n\x1b[1;33m⚠ SSH Connection Closed\x1b[0m');
        terminal.current.writeln('Click "Connect" to reconnect...\r\n');
        
        // No cleanup needed for simplified implementation
      }
      
      // Cleanup attach addon
      if (attachAddon.current) {
        attachAddon.current.dispose();
        attachAddon.current = null;
      }
    };

    websocket.current.onerror = (error) => {
      console.error('WebSocket error:', error);
      setConnectionStatus({ 
        status: 'failed', 
        message: 'Connection failed - check SSH credentials' 
      });
      
      if (terminal.current) {
        terminal.current.writeln('\r\n\x1b[1;31m✗ SSH Connection Failed\x1b[0m');
        terminal.current.writeln('Please verify SSH credentials and try again.\r\n');
      }
    };

    websocket.current.onmessage = (event) => {
      // Handle special control messages
      if (event.data.startsWith('ERROR:')) {
        const errorMessage = event.data.substring(6);
        setConnectionStatus({ status: 'failed', message: errorMessage });
        
        if (terminal.current) {
          terminal.current.writeln(`\r\n\x1b[1;31m✗ ${errorMessage}\x1b[0m\r\n`);
        }
      }
    };
  };

  const disconnect = () => {
    if (websocket.current) {
      websocket.current.close();
    }
    
    // Simple cleanup - no complex scroll management needed
  };

  const clearTerminal = () => {
    if (terminal.current) {
      terminal.current.clear();
      terminal.current.writeln('\x1b[1;36mOpenWatch Terminal\x1b[0m');
      terminal.current.writeln(`Host: ${hostname} (${ipAddress})`);
      if (connectionStatus.status === 'connected') {
        terminal.current.writeln('SSH session active...\r\n');
      } else {
        terminal.current.writeln('Click "Connect" to establish SSH connection...\r\n');
      }
      // Scroll to bottom and focus after clearing
      terminal.current.scrollToLine(terminal.current.buffer.active.baseY + terminal.current.buffer.active.cursorY);
      terminal.current.focus();
    }
  };

  const getStatusColor = () => {
    switch (connectionStatus.status) {
      case 'connected': return 'success';
      case 'connecting': return 'info';
      case 'failed': return 'error';
      case 'closed': return 'warning';
      default: return 'default';
    }
  };

  const getStatusLabel = () => {
    switch (connectionStatus.status) {
      case 'connected': return 'Connected';
      case 'connecting': return 'Connecting';
      case 'failed': return 'Failed';
      case 'closed': return 'Disconnected';
      default: return 'Disconnected';
    }
  };

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Terminal Header */}
      <Box sx={{ 
        p: 2, 
        bgcolor: 'grey.100', 
        borderBottom: 1, 
        borderColor: 'divider',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <TerminalIcon color="primary" />
          <Typography variant="h6">
            SSH Terminal - {hostname}
          </Typography>
          <Chip 
            label={getStatusLabel()} 
            color={getStatusColor() as any}
            size="small"
            icon={connectionStatus.status === 'connecting' ? 
              <CircularProgress size={16} /> : undefined
            }
          />
        </Box>
        
        <Box sx={{ display: 'flex', gap: 1 }}>
          {connectionStatus.status === 'connected' ? (
            <Button
              variant="outlined"
              size="small"
              startIcon={<CloseIcon />}
              onClick={disconnect}
              color="error"
            >
              Disconnect
            </Button>
          ) : (
            <Button
              variant="contained"
              size="small"
              startIcon={<TerminalIcon />}
              onClick={connect}
              disabled={connectionStatus.status === 'connecting'}
            >
              Connect
            </Button>
          )}
          <Button
            variant="outlined"
            size="small"
            startIcon={<RefreshIcon />}
            onClick={clearTerminal}
          >
            Clear
          </Button>
        </Box>
      </Box>

      {/* Status Message */}
      {connectionStatus.message && (
        <Alert 
          severity={connectionStatus.status === 'failed' ? 'error' : 'info'} 
          sx={{ m: 2, mb: 1 }}
        >
          {connectionStatus.message}
        </Alert>
      )}

      {/* Terminal Container */}
      <Box 
        sx={{ 
          flexGrow: 1, 
          p: 1,
          bgcolor: '#1a1a1a',
          overflow: 'hidden',
          minHeight: '400px'
        }}
      >
        <Box
          ref={terminalRef}
          sx={{
            width: '100%',
            height: '100%',
            minHeight: '380px',
            '& .xterm': {
              height: '100% !important',
              width: '100% !important',
            },
            '& .xterm-viewport': {
              overflow: 'hidden',
            },
            '& .xterm-screen': {
              width: '100% !important',
              height: '100% !important',
            }
          }}
        />
      </Box>

      {/* Footer */}
      <Box sx={{ 
        p: 1, 
        bgcolor: 'grey.50', 
        borderTop: 1, 
        borderColor: 'divider',
        fontSize: '0.75rem',
        color: 'text.secondary'
      }}>
        <Typography variant="caption">
          Terminal session for testing SSH connectivity. 
          Use this terminal to verify that SSH credentials are working properly.
        </Typography>
      </Box>
    </Box>
  );
};

export default HostTerminal;