/**
 * Network Tab
 *
 * Displays network interfaces, firewall rules, and routes.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/NetworkTab
 */

import React, { useState } from 'react';
import {
  Box,
  Typography,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Alert,
  CircularProgress,
} from '@mui/material';
import { useNetwork, useFirewall, useRoutes } from '../../../../hooks/useHostDetail';

interface NetworkTabProps {
  hostId: string;
}

interface SubTabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function SubTabPanel(props: SubTabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 2 }}>{children}</Box>}
    </div>
  );
}

const NetworkTab: React.FC<NetworkTabProps> = ({ hostId }) => {
  const [subTab, setSubTab] = useState(0);

  const { data: networkData, isLoading: networkLoading, error: networkError } = useNetwork(hostId);
  const {
    data: firewallData,
    isLoading: firewallLoading,
    error: firewallError,
  } = useFirewall(hostId);
  const { data: routesData, isLoading: routesLoading, error: routesError } = useRoutes(hostId);

  return (
    <Box>
      <Tabs value={subTab} onChange={(_, newValue) => setSubTab(newValue)}>
        <Tab label={`Interfaces (${networkData?.total || 0})`} />
        <Tab label={`Firewall (${firewallData?.total || 0})`} />
        <Tab label={`Routes (${routesData?.total || 0})`} />
      </Tabs>

      {/* Interfaces */}
      <SubTabPanel value={subTab} index={0}>
        {networkLoading ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : networkError ? (
          <Alert severity="error">Failed to load network interfaces</Alert>
        ) : !networkData || networkData.total === 0 ? (
          <Alert severity="info">No network interface data available.</Alert>
        ) : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Interface</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>IP Addresses</TableCell>
                  <TableCell>MAC Address</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>MTU</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {networkData.items.map((iface, idx) => (
                  <TableRow key={`${iface.interfaceName}-${idx}`} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {iface.interfaceName}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Box
                          sx={{
                            width: 8,
                            height: 8,
                            borderRadius: '50%',
                            bgcolor: iface.isUp ? 'success.main' : 'error.main',
                          }}
                        />
                        <Typography variant="body2">{iface.isUp ? 'Up' : 'Down'}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      {iface.ipAddresses && iface.ipAddresses.length > 0 ? (
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                          {iface.ipAddresses.map((ip, ipIdx) => (
                            <Typography
                              key={ipIdx}
                              variant="body2"
                              sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                            >
                              {ip.address}/{ip.prefixLength}
                            </Typography>
                          ))}
                        </Box>
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          -
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                      >
                        {iface.macAddress || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{iface.interfaceType || '-'}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{iface.mtu || '-'}</Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </SubTabPanel>

      {/* Firewall */}
      <SubTabPanel value={subTab} index={1}>
        {firewallLoading ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : firewallError ? (
          <Alert severity="error">Failed to load firewall rules</Alert>
        ) : !firewallData || firewallData.total === 0 ? (
          <Alert severity="info">No firewall rules collected or firewall may be disabled.</Alert>
        ) : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>#</TableCell>
                  <TableCell>Chain</TableCell>
                  <TableCell>Action</TableCell>
                  <TableCell>Protocol</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Destination</TableCell>
                  <TableCell>Port</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {firewallData.items.map((rule, idx) => (
                  <TableRow key={idx} hover>
                    <TableCell>
                      <Typography variant="body2">{rule.ruleNumber ?? idx + 1}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{rule.chain || '-'}</Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={rule.action || 'unknown'}
                        color={
                          rule.action?.toLowerCase() === 'accept'
                            ? 'success'
                            : rule.action?.toLowerCase() === 'drop' ||
                                rule.action?.toLowerCase() === 'reject'
                              ? 'error'
                              : 'default'
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{rule.protocol || 'any'}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                      >
                        {rule.source || 'any'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                      >
                        {rule.destination || 'any'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{rule.port || '-'}</Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </SubTabPanel>

      {/* Routes */}
      <SubTabPanel value={subTab} index={2}>
        {routesLoading ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : routesError ? (
          <Alert severity="error">Failed to load routes</Alert>
        ) : !routesData || routesData.total === 0 ? (
          <Alert severity="info">No routing table data available.</Alert>
        ) : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Destination</TableCell>
                  <TableCell>Gateway</TableCell>
                  <TableCell>Interface</TableCell>
                  <TableCell>Metric</TableCell>
                  <TableCell>Type</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {routesData.items.map((route, idx) => (
                  <TableRow key={idx} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography
                          variant="body2"
                          sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                        >
                          {route.destination}
                        </Typography>
                        {route.isDefault && <Chip size="small" label="default" color="primary" />}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                      >
                        {route.gateway || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{route.interface || '-'}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{route.metric ?? '-'}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{route.routeType || '-'}</Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </SubTabPanel>
    </Box>
  );
};

export default NetworkTab;
