/**
 * Scan Information tab content.
 *
 * Displays scan configuration details, technical details,
 * and scan options in a two-column layout.
 */

import React from 'react';
import { List, ListItem, ListItemText, Paper, Typography } from '@mui/material';
import Grid from '@mui/material/Grid';
import type { ScanDetails } from './scanTypes';

interface ScanInformationTabProps {
  scan: ScanDetails;
}

const ScanInformationTab: React.FC<ScanInformationTabProps> = ({ scan }) => {
  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 12, md: 6 }}>
        <Typography variant="h6" gutterBottom>
          Scan Configuration
        </Typography>
        <List>
          <ListItem>
            <ListItemText primary="Scan Name" secondary={scan.name} />
          </ListItem>
          <ListItem>
            <ListItemText primary="Scan ID" secondary={scan.id} />
          </ListItem>
          <ListItem>
            <ListItemText primary="Profile ID" secondary={scan.profile_id} />
          </ListItem>
          <ListItem>
            <ListItemText
              primary="Started At"
              secondary={new Date(scan.started_at).toLocaleString()}
            />
          </ListItem>
          {scan.completed_at && (
            <ListItem>
              <ListItemText
                primary="Completed At"
                secondary={new Date(scan.completed_at).toLocaleString()}
              />
            </ListItem>
          )}
          <ListItem>
            <ListItemText
              primary="Duration"
              secondary={
                scan.completed_at
                  ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)} seconds`
                  : 'In progress...'
              }
            />
          </ListItem>
        </List>
      </Grid>

      <Grid size={{ xs: 12, md: 6 }}>
        <Typography variant="h6" gutterBottom>
          Technical Details
        </Typography>
        <List>
          <ListItem>
            <ListItemText primary="Result File" secondary={scan.result_file || 'Not available'} />
          </ListItem>
          <ListItem>
            <ListItemText primary="Report File" secondary={scan.report_file || 'Not available'} />
          </ListItem>
          {scan.error_message && (
            <ListItem>
              <ListItemText
                primary="Error Message"
                secondary={scan.error_message}
                secondaryTypographyProps={{ color: 'error' }}
              />
            </ListItem>
          )}
        </List>

        {scan.scan_options &&
        typeof scan.scan_options === 'object' &&
        Object.keys(scan.scan_options as Record<string, unknown>).length > 0 ? (
          <>
            <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
              Scan Options
            </Typography>
            <Paper variant="outlined" sx={{ p: 2 }}>
              <pre style={{ margin: 0, overflow: 'auto' }}>
                {JSON.stringify(scan.scan_options, null, 2)}
              </pre>
            </Paper>
          </>
        ) : null}
      </Grid>
    </Grid>
  );
};

export default ScanInformationTab;
