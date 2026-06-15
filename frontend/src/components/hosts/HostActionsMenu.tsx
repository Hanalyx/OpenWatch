import { useEffect, useRef, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { MoreVertical, Pencil, Trash2, Loader2, AlertTriangle } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useAuthStore } from '@/store/useAuthStore';
import { Modal, Btn, Callout } from '@/components/settings/primitives';
import { EditHostModal } from '@/components/hosts/EditHostModal';

// HostActionsMenu — the three-dot (kebab) menu that surfaces Edit + Delete
// for a host. Used on the /hosts cards + rows and the host-detail header.
//
// Permission-gated per the RBAC registry: Edit needs host:write, Delete
// needs host:delete (dangerous). A user with neither sees no menu at all.
// Delete always goes through an explicit confirmation modal.
//
// On the list, Edit fetches the full host first (the list row carries only
// a summary shape); on detail the parent already has it, but this component
// is self-contained so it fetches there too. After a delete, the detail
// variant navigates back to /hosts; the list variant just invalidates.
//
// Dropdown behaviour (Escape + click-outside to close) mirrors the shell
// AccountMenu.

interface FullHost {
  id: string;
  hostname: string;
  ip_address: string;
  port?: number;
  environment?: string;
  display_name?: string;
  description?: string;
  username?: string;
  tags?: string[];
}

interface Props {
  hostId: string;
  hostname: string;
  // Show the Edit item (list). Detail passes false — it has its own Edit
  // button next to the kebab.
  showEdit?: boolean;
  // Where to go after a successful delete.
  afterDelete?: 'navigate' | 'invalidate';
  // Style for the trigger button so it matches each call site's icon button.
  buttonStyle?: React.CSSProperties;
  iconSize?: number;
}

export function HostActionsMenu({
  hostId,
  hostname,
  showEdit = true,
  afterDelete = 'invalidate',
  buttonStyle,
  iconSize = 14,
}: Props) {
  const canWrite = useAuthStore((s) => s.hasPermission('host:write'));
  const canDelete = useAuthStore((s) => s.hasPermission('host:delete'));
  const [open, setOpen] = useState(false);
  const [editHost, setEditHost] = useState<FullHost | null>(null);
  const [loadingEdit, setLoadingEdit] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const showEditItem = showEdit && canWrite;

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    const onMouseDown = (e: MouseEvent) => {
      if (!wrapperRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onMouseDown);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onMouseDown);
    };
  }, [open]);

  // A user with no applicable action gets no menu.
  if (!showEditItem && !canDelete) return null;

  const startEdit = async () => {
    setOpen(false);
    setEditError(null);
    setLoadingEdit(true);
    try {
      const { data, response, error } = await api.GET('/api/v1/hosts/{id}', {
        params: { path: { id: hostId } },
      });
      if (!response.ok || !data) {
        throw new Error(apiErrorMessage(error, `Failed to load host (HTTP ${response.status})`));
      }
      // GET /hosts/{id} wraps the record under `host` (alongside liveness +
      // compliance_summary). The edit form needs the unwrapped host so its
      // fields pre-fill — passing the wrapper leaves every field blank.
      const wrapper = data as unknown as { host?: FullHost };
      const full = (wrapper.host ?? (data as unknown as FullHost)) as FullHost;
      setEditHost(full);
    } catch (e) {
      setEditError((e as Error).message);
    } finally {
      setLoadingEdit(false);
    }
  };

  return (
    <div ref={wrapperRef} style={{ position: 'relative', display: 'inline-flex' }}>
      <button
        type="button"
        aria-label={`Actions for ${hostname}`}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        style={buttonStyle ?? defaultBtn}
      >
        {loadingEdit ? <Loader2 size={iconSize} /> : <MoreVertical size={iconSize} />}
      </button>

      {open && (
        <div
          role="menu"
          aria-label={`Actions for ${hostname}`}
          style={{
            position: 'absolute',
            top: 30,
            right: 0,
            minWidth: 168,
            background: 'var(--ow-bg-1)',
            border: '1px solid var(--ow-line)',
            borderRadius: 8,
            boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
            padding: '6px 0',
            zIndex: 50,
          }}
        >
          {showEditItem && (
            <button type="button" role="menuitem" onClick={startEdit} style={menuItem}>
              <Pencil size={13} /> Edit host
            </button>
          )}
          {canDelete && (
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setOpen(false);
                setConfirmDelete(true);
              }}
              style={{ ...menuItem, color: 'var(--ow-crit)' }}
            >
              <Trash2 size={13} /> Delete host
            </button>
          )}
        </div>
      )}

      {editError && (
        <div style={{ position: 'absolute', top: 30, right: 0, zIndex: 50, width: 240 }}>
          <Callout tier="crit">{editError}</Callout>
        </div>
      )}

      {editHost && <EditHostModal open onClose={() => setEditHost(null)} host={editHost} />}

      {confirmDelete && (
        <DeleteHostModal
          hostId={hostId}
          hostname={hostname}
          afterDelete={afterDelete}
          onClose={() => setConfirmDelete(false)}
        />
      )}
    </div>
  );
}

// DeleteHostModal — explicit confirmation before DELETE /api/v1/hosts/{id}
// (host:delete). Deletion removes the host record and its scan-history
// pointer and cannot be undone, so the operator must confirm.
function DeleteHostModal({
  hostId,
  hostname,
  afterDelete,
  onClose,
}: {
  hostId: string;
  hostname: string;
  afterDelete: 'navigate' | 'invalidate';
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  const deleteMutation = useMutation({
    mutationFn: async () => {
      const { response, error: e } = await api.DELETE('/api/v1/hosts/{id}', {
        params: { path: { id: hostId } },
      });
      if (!response.ok) {
        throw new Error(apiErrorMessage(e, `Failed to delete host (HTTP ${response.status})`));
      }
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['hosts'] });
      queryClient.removeQueries({ queryKey: ['host', hostId] });
      onClose();
      if (afterDelete === 'navigate') {
        navigate({ to: '/hosts' });
      }
    },
    onError: (e: Error) => setError(e.message),
  });

  const submitting = deleteMutation.isPending;

  return (
    <Modal
      open
      onClose={() => {
        if (!submitting) onClose();
      }}
      title="Delete host"
      width={460}
      preventClose={submitting}
      footer={
        <>
          <Btn onClick={onClose} disabled={submitting}>
            Cancel
          </Btn>
          <Btn
            variant="danger"
            disabled={submitting}
            onClick={() => {
              setError(null);
              deleteMutation.mutate();
            }}
          >
            {submitting ? (
              <>
                <Loader2 size={14} /> Deleting…
              </>
            ) : (
              <>
                <Trash2 size={14} /> Delete host
              </>
            )}
          </Btn>
        </>
      }
    >
      <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
        <AlertTriangle size={20} style={{ color: 'var(--ow-crit)', flexShrink: 0, marginTop: 2 }} />
        <div style={{ fontSize: 13, color: 'var(--ow-fg-1)', lineHeight: 1.5 }}>
          Delete{' '}
          <strong style={{ color: 'var(--ow-fg-0)', fontFamily: 'var(--ow-font-mono)' }}>
            {hostname}
          </strong>
          ? This removes the host record and its scan-history pointer. This action cannot be undone.
        </div>
      </div>
      {error && (
        <div style={{ marginTop: 12 }}>
          <Callout tier="crit">{error}</Callout>
        </div>
      )}
    </Modal>
  );
}

const defaultBtn: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: 28,
  height: 28,
  background: 'transparent',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-2)',
  cursor: 'pointer',
  padding: 0,
};

const menuItem: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  width: '100%',
  padding: '8px 12px',
  background: 'transparent',
  border: 0,
  color: 'var(--ow-fg-0)',
  textAlign: 'left',
  fontSize: 13,
  cursor: 'pointer',
};
