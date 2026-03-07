/**
 * Confirmation dialogs for host management actions.
 *
 * Contains Delete, Bulk Action, and Quick Scan confirmation dialogs.
 */

import React from 'react';
import {
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Typography,
} from '@mui/material';
import type { Host } from '../../../types/host';

interface HostConfirmDialogsProps {
  deleteDialog: { open: boolean; host: Host | null };
  setDeleteDialog: (val: { open: boolean; host: Host | null }) => void;
  deletingHost: boolean;
  confirmDelete: () => void;

  bulkActionDialog: boolean;
  setBulkActionDialog: (open: boolean) => void;
  selectedBulkAction: string;
  selectedHostCount: number;
  executeBulkAction: () => void;

  quickScanDialog: { open: boolean; host: Host | null };
  setQuickScanDialog: (val: { open: boolean; host: Host | null }) => void;
  handleQuickScanWithValidation: (host: Host) => Promise<void>;
}

const HostConfirmDialogs: React.FC<HostConfirmDialogsProps> = ({
  deleteDialog,
  setDeleteDialog,
  deletingHost,
  confirmDelete,
  bulkActionDialog,
  setBulkActionDialog,
  selectedBulkAction,
  selectedHostCount,
  executeBulkAction,
  quickScanDialog,
  setQuickScanDialog,
  handleQuickScanWithValidation,
}) => {
  return (
    <>
      <Dialog
        open={deleteDialog.open}
        onClose={() => setDeleteDialog({ open: false, host: null })}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Delete Host</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete <strong>{deleteDialog.host?.displayName}</strong>? This
            action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setDeleteDialog({ open: false, host: null })}
            disabled={deletingHost}
          >
            Cancel
          </Button>
          <Button onClick={confirmDelete} color="error" variant="contained" disabled={deletingHost}>
            {deletingHost ? 'Deleting...' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={bulkActionDialog}
        onClose={() => setBulkActionDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Confirm Bulk Action</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to perform <strong>{selectedBulkAction}</strong> on{' '}
            {selectedHostCount} selected hosts?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBulkActionDialog(false)}>Cancel</Button>
          <Button onClick={executeBulkAction} variant="contained">
            Confirm
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={quickScanDialog.open}
        onClose={() => setQuickScanDialog({ open: false, host: null })}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Quick Scan</DialogTitle>
        <DialogContent>
          <Typography>
            Start a compliance scan for <strong>{quickScanDialog.host?.displayName}</strong>?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setQuickScanDialog({ open: false, host: null })}>Cancel</Button>
          <Button
            variant="contained"
            onClick={() =>
              quickScanDialog.host && handleQuickScanWithValidation(quickScanDialog.host)
            }
          >
            Start Scan
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default HostConfirmDialogs;
