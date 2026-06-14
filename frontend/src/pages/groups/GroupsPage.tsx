import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Plus, Boxes, Building2, MonitorCog, MoreVertical } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';
import { Modal, Btn, FormField, Select, Toggle, Callout } from '@/components/settings/primitives';
import { useAuthStore } from '@/store/useAuthStore';

// GroupsPage — the Groups overview at /groups.
//
// Ported from docs/engineering/prototypes/openwatch-v1/Groups.html.
// Organizes hosts into two kinds: "site" (environment & topology role,
// always manual membership) and "os_category" (platform & workload,
// either manual or auto-populated from an OS family match).
//
// Reads GET /api/v1/groups (summary + per-group rollups) behind
// host:read. Mutations (create / delete / maintenance toggle) require
// host:write and invalidate the ['groups'] query on success.

type GroupWithRollup = components['schemas']['GroupWithRollup'];
type GroupSummary = components['schemas']['GroupSummary'];
type GroupMember = components['schemas']['GroupMember'];

// ── helpers ────────────────────────────────────────────────────────

// Map a group's design-token color key (e.g. "info", "rhel", "ubuntu")
// to a concrete swatch color. Unknown keys fall back to the info token.
function swatchColor(key: string): string {
  const k = (key || '').trim().toLowerCase();
  const TOKEN: Record<string, string> = {
    info: 'var(--ow-info)',
    ok: 'var(--ow-ok)',
    warn: 'var(--ow-warn)',
    crit: 'var(--ow-crit)',
    rhel: 'var(--ow-os-rhel)',
    ubuntu: 'var(--ow-os-ubuntu)',
    debian: 'var(--ow-os-debian)',
    suse: 'var(--ow-os-suse)',
  };
  return TOKEN[k] ?? 'var(--ow-info)';
}

// Compliance band -> tone color. null (nothing scanned) reads as crit.
function complianceTone(pct: number | null | undefined): string {
  if (pct == null) return 'var(--ow-crit)';
  if (pct < 40) return 'var(--ow-crit)';
  if (pct < 80) return 'var(--ow-warn)';
  return 'var(--ow-ok)';
}

function statusDotColor(status: string): string {
  if (status === 'online') return 'var(--ow-ok)';
  if (status === 'down') return 'var(--ow-crit)';
  return 'var(--ow-fg-3)';
}

// ── page ───────────────────────────────────────────────────────────

export function GroupsPage() {
  const canWrite = useAuthStore((s) => s.hasPermission('host:write'));
  const [createOpen, setCreateOpen] = useState(false);

  const q = useQuery({
    queryKey: ['groups'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/groups', {});
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load groups (HTTP ${response.status})`));
      }
      return data!;
    },
  });

  const summary = q.data?.summary;
  const groups = q.data?.groups ?? [];
  const sites = groups.filter((g) => g.kind === 'site');
  const osCategories = groups.filter((g) => g.kind === 'os_category');

  return (
    <div style={{ padding: '20px 28px 60px' }}>
      <title>Groups · OpenWatch</title>

      <header
        style={{
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          gap: 24,
          marginBottom: 18,
        }}
      >
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: '-0.01em' }}>
            Groups
          </h1>
          <p style={{ color: 'var(--ow-fg-2)', fontSize: 13, marginTop: 4, maxWidth: 720 }}>
            Organize hosts by site (environment and topology role) and OS category (platform and
            workload). A host can belong to many groups.
          </p>
        </div>
        {canWrite && (
          <Btn variant="primary" onClick={() => setCreateOpen(true)}>
            <Plus size={14} />
            New group
          </Btn>
        )}
      </header>

      {/* KPI row */}
      {q.isPending ? (
        <StateMsg kind="loading" />
      ) : q.isError ? (
        <StateMsg kind="error" message={(q.error as Error)?.message} />
      ) : (
        <>
          <KpiRow summary={summary!} />

          <GroupSection
            title="Sites"
            badge="Site"
            badgeKind="site"
            description="Environment and topology role. Hosts assigned manually."
            groups={sites}
            canWrite={canWrite}
            emptyText="No sites yet. Create one to group hosts by environment."
          />

          <GroupSection
            title="OS categories"
            badge="OS category"
            badgeKind="os"
            description="Platform and workload. OS-family groups auto-populate from capability detection."
            groups={osCategories}
            canWrite={canWrite}
            emptyText="No OS categories yet. Create one to group hosts by platform or workload."
          />
        </>
      )}

      <CreateGroupModal open={createOpen} onClose={() => setCreateOpen(false)} />
    </div>
  );
}

// ── KPI row ────────────────────────────────────────────────────────

function KpiRow({ summary }: { summary: GroupSummary }) {
  const avg = summary.avg_compliance_pct;
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: 12,
        marginBottom: 18,
      }}
    >
      <Kpi
        label="Groups"
        value={summary.groups}
        sub={`${summary.sites} sites / ${summary.os_categories} OS categories`}
      />
      <Kpi
        label="Hosts in maintenance"
        value={summary.hosts_maintenance}
        sub={summary.hosts_maintenance > 0 ? 'scanning paused' : 'none paused'}
        tone={summary.hosts_maintenance > 0 ? 'var(--ow-warn)' : undefined}
      />
      <Kpi
        label="Avg compliance"
        value={avg == null ? '—' : `${avg}%`}
        sub="across scanned hosts"
        tone={complianceTone(avg)}
      />
      <Kpi
        label="Ungrouped"
        value={summary.ungrouped}
        sub={summary.ungrouped === 0 ? 'All hosts grouped' : 'hosts in no group'}
      />
    </div>
  );
}

function Kpi({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  tone?: string;
}) {
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '14px 16px',
      }}
    >
      <div
        style={{
          color: 'var(--ow-fg-2)',
          fontSize: 12,
          fontWeight: 500,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 28,
          fontWeight: 600,
          letterSpacing: '-0.02em',
          marginTop: 8,
          lineHeight: 1,
          fontVariantNumeric: 'tabular-nums',
          color: tone ?? 'var(--ow-fg-0)',
        }}
      >
        {value}
      </div>
      {sub && <div style={{ color: 'var(--ow-fg-3)', fontSize: 12, marginTop: 8 }}>{sub}</div>}
    </div>
  );
}

// ── section ────────────────────────────────────────────────────────

function GroupSection({
  title,
  badge,
  badgeKind,
  description,
  groups,
  canWrite,
  emptyText,
}: {
  title: string;
  badge: string;
  badgeKind: 'site' | 'os';
  description: string;
  groups: GroupWithRollup[];
  canWrite: boolean;
  emptyText: string;
}) {
  const badgeColor = badgeKind === 'site' ? 'var(--ow-info)' : 'var(--ow-brand-2)';
  const badgeBg = badgeKind === 'site' ? 'var(--ow-info-bg)' : 'var(--ow-bg-3)';
  return (
    <section style={{ marginTop: 14, marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
        <h2
          style={{
            margin: 0,
            fontSize: 15,
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
          }}
        >
          {title}
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              height: 22,
              padding: '0 10px',
              borderRadius: 'var(--ow-radius-full)',
              fontSize: 11,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              background: badgeBg,
              color: badgeColor,
            }}
          >
            {badgeKind === 'site' ? <Building2 size={11} /> : <MonitorCog size={11} />}
            {badge}
          </span>
        </h2>
        <span style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>{description}</span>
      </div>

      {groups.length === 0 ? (
        <div
          style={{
            color: 'var(--ow-fg-3)',
            fontSize: 13,
            padding: '20px 0',
          }}
        >
          {emptyText}
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
            gap: 14,
          }}
        >
          {groups.map((g) => (
            <GroupCard key={g.id} group={g} canWrite={canWrite} />
          ))}
        </div>
      )}
    </section>
  );
}

// ── group card ─────────────────────────────────────────────────────

function GroupCard({ group, canWrite }: { group: GroupWithRollup; canWrite: boolean }) {
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);
  const r = group.rollup;
  const total = r.hosts;
  const onPct = total ? (r.online / total) * 100 : 0;
  const downPct = total ? (r.down / total) * 100 : 0;

  const maintMutation = useMutation({
    mutationFn: async (on: boolean) => {
      const { response, error } = await api.POST('/api/v1/groups/{id}:maintenance', {
        params: { path: { id: group.id } },
        body: { on },
      });
      if (!response.ok) {
        throw new Error(
          apiErrorMessage(error, `Failed to update maintenance (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['groups'] });
    },
    onError: (err: Error) => setActionError(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      const { response, error } = await api.DELETE('/api/v1/groups/{id}', {
        params: { path: { id: group.id } },
      });
      if (!response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to delete group (HTTP ${response.status})`));
      }
    },
    onSuccess: () => {
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['groups'] });
    },
    onError: (err: Error) => setActionError(err.message),
  });

  const busy = maintMutation.isPending || deleteMutation.isPending;
  const chips = r.members.slice(0, 4);
  const moreCount = total - chips.length;

  return (
    <div
      style={{
        background: group.maintenance
          ? 'linear-gradient(180deg, color-mix(in oklab, var(--ow-warn-bg) 30%, transparent), var(--ow-bg-1) 60%)'
          : 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 16,
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
      }}
    >
      {/* head */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div
          style={{
            width: 38,
            height: 38,
            borderRadius: 9,
            background: swatchColor(group.color),
            display: 'grid',
            placeItems: 'center',
            color: '#fff',
            flexShrink: 0,
          }}
        >
          {group.kind === 'site' ? <Building2 size={18} /> : <Boxes size={18} />}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 15, fontWeight: 600 }}>{group.name}</div>
          <div
            style={{
              color: 'var(--ow-fg-2)',
              fontSize: 12,
              marginTop: 3,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              flexWrap: 'wrap',
            }}
          >
            {group.subtype && <span>{group.subtype}</span>}
            {group.subtype && <span style={{ color: 'var(--ow-fg-3)' }}>·</span>}
            {group.membership === 'auto' ? (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  color: 'var(--ow-info)',
                  fontWeight: 500,
                }}
              >
                auto
                {group.match_family && (
                  <span
                    style={{
                      fontFamily: 'var(--ow-font-mono)',
                      fontSize: 11,
                      color: 'var(--ow-fg-1)',
                    }}
                  >
                    os.family = {group.match_family}
                  </span>
                )}
              </span>
            ) : (
              <span style={{ color: 'var(--ow-fg-3)' }}>manual</span>
            )}
          </div>
        </div>
        {canWrite && (
          <button
            type="button"
            aria-label={`Delete ${group.name}`}
            title="Delete group"
            disabled={busy}
            onClick={() => {
              if (
                window.confirm(
                  `Delete group "${group.name}"? Member hosts are not deleted, only the grouping.`,
                )
              ) {
                deleteMutation.mutate();
              }
            }}
            style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              border: '1px solid var(--ow-line)',
              background: 'var(--ow-bg-1)',
              color: 'var(--ow-fg-2)',
              cursor: busy ? 'not-allowed' : 'pointer',
              display: 'grid',
              placeItems: 'center',
              flexShrink: 0,
            }}
          >
            <MoreVertical size={14} />
          </button>
        )}
      </div>

      {/* rollup bar */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div
          style={{
            height: 8,
            background: 'var(--ow-bg-3)',
            borderRadius: 4,
            overflow: 'hidden',
            display: 'flex',
          }}
        >
          <span style={{ width: `${onPct}%`, background: 'var(--ow-ok)', height: '100%' }} />
          <span style={{ width: `${downPct}%`, background: 'var(--ow-crit)', height: '100%' }} />
        </div>
        <div
          style={{
            display: 'flex',
            gap: 14,
            fontSize: 12,
            color: 'var(--ow-fg-2)',
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          <span>
            <span style={{ fontWeight: 600 }}>{total}</span> hosts
          </span>
          <span>
            <span style={{ fontWeight: 600, color: 'var(--ow-ok)' }}>{r.online}</span> online
          </span>
          <span>
            <span style={{ fontWeight: 600, color: 'var(--ow-crit)' }}>{r.down}</span> down
          </span>
        </div>
      </div>

      {/* metrics */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 0',
          borderTop: '1px dashed var(--ow-line)',
          borderBottom: '1px dashed var(--ow-line)',
        }}
      >
        <Metric
          label="Avg compliance"
          value={r.avg_compliance_pct == null ? '—' : `${r.avg_compliance_pct}%`}
          tone={complianceTone(r.avg_compliance_pct)}
        />
        <Metric
          label="Critical hosts"
          value={r.critical_hosts}
          tone={r.critical_hosts ? 'var(--ow-crit)' : 'var(--ow-fg-0)'}
        />
        <Metric label="Down" value={r.down} tone={r.down ? 'var(--ow-crit)' : 'var(--ow-ok)'} />
      </div>

      {/* member chips */}
      {total > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {chips.map((m) => (
            <HostChip key={m.host_id} member={m} />
          ))}
          {moreCount > 0 && (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                height: 22,
                padding: '0 8px',
                borderRadius: 'var(--ow-radius-full)',
                border: '1px dashed var(--ow-line)',
                color: 'var(--ow-fg-3)',
                fontSize: 11,
              }}
            >
              +{moreCount}
            </span>
          )}
        </div>
      )}

      {actionError && (
        <div role="alert" style={{ fontSize: 12, color: 'var(--ow-crit)' }}>
          {actionError}
        </div>
      )}

      {/* foot: maintenance toggle */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
        }}
      >
        {group.maintenance ? (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              height: 24,
              padding: '0 10px',
              borderRadius: 'var(--ow-radius-full)',
              fontSize: 11,
              fontWeight: 600,
              background: 'var(--ow-warn-bg)',
              color: 'var(--ow-warn)',
            }}
          >
            <span
              style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor' }}
            />
            Maintenance
          </span>
        ) : (
          <span style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>Active</span>
        )}
        {canWrite && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>Maintenance</span>
            <Toggle
              value={group.maintenance}
              disabled={busy}
              ariaLabel={`Toggle maintenance for ${group.name}`}
              onChange={(next) => maintMutation.mutate(next)}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: React.ReactNode; tone: string }) {
  return (
    <div>
      <div
        style={{
          color: 'var(--ow-fg-3)',
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 18,
          fontWeight: 600,
          marginTop: 2,
          fontVariantNumeric: 'tabular-nums',
          color: tone,
        }}
      >
        {value}
      </div>
    </div>
  );
}

function HostChip({ member }: { member: GroupMember }) {
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        height: 22,
        padding: '0 8px',
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius-full)',
        fontSize: 11,
        fontFamily: 'var(--ow-font-mono)',
        color: 'var(--ow-fg-1)',
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: statusDotColor(member.status),
        }}
      />
      {member.hostname}
    </span>
  );
}

// ── create modal ───────────────────────────────────────────────────

const createSchema = z
  .object({
    name: z.string().min(1, 'Name is required').max(128),
    kind: z.enum(['site', 'os_category']),
    subtype: z.string().max(128).optional(),
    membership: z.enum(['manual', 'auto']),
    match_family: z.string().max(64).optional(),
  })
  .refine((v) => v.membership !== 'auto' || (v.match_family && v.match_family.trim().length > 0), {
    message: 'Auto membership requires an OS family',
    path: ['match_family'],
  })
  .refine((v) => v.kind !== 'site' || v.membership === 'manual', {
    message: 'Sites must use manual membership',
    path: ['membership'],
  });

type CreateForm = z.infer<typeof createSchema>;

function CreateGroupModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);
  const { register, handleSubmit, reset, watch, setValue, formState } = useForm<CreateForm>({
    resolver: zodResolver(createSchema),
    mode: 'onTouched',
    defaultValues: {
      name: '',
      kind: 'site',
      subtype: '',
      membership: 'manual',
      match_family: '',
    },
  });

  const kind = watch('kind');
  const membership = watch('membership');

  const createMutation = useMutation({
    mutationFn: async (values: CreateForm) => {
      const body: components['schemas']['GroupCreate'] = {
        name: values.name,
        kind: values.kind,
        membership: values.membership,
      };
      if (values.subtype && values.subtype.trim()) body.subtype = values.subtype.trim();
      if (values.membership === 'auto' && values.match_family) {
        body.match_family = values.match_family.trim();
      }
      const { response, error } = await api.POST('/api/v1/groups', { body });
      if (!response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to create group (HTTP ${response.status})`));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['groups'] });
      reset();
      setServerError(null);
      onClose();
    },
    onError: (err: Error) => setServerError(err.message),
  });

  const submitting = createMutation.isPending;

  const handleClose = () => {
    if (submitting) return;
    reset();
    setServerError(null);
    onClose();
  };

  const onSubmit = (values: CreateForm) => {
    setServerError(null);
    createMutation.mutate(values);
  };

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="New group"
      width={520}
      preventClose={submitting}
      footer={
        <>
          <Btn onClick={handleClose} disabled={submitting}>
            Cancel
          </Btn>
          <Btn
            variant="primary"
            type="submit"
            disabled={submitting}
            onClick={() => {
              void handleSubmit(onSubmit)();
            }}
          >
            {submitting ? 'Creating…' : 'Create group'}
          </Btn>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)} noValidate>
        <FormField label="Name" error={formState.errors.name?.message}>
          <input type="text" autoFocus {...register('name')} style={inputStyle} />
        </FormField>

        <FormField
          label="Kind"
          hint="Sites group by environment; OS categories group by platform or workload."
        >
          <Select
            ariaLabel="Group kind"
            value={kind}
            width="100%"
            options={[
              { value: 'site', label: 'Site' },
              { value: 'os_category', label: 'OS category' },
            ]}
            onChange={(v) => {
              setValue('kind', v as CreateForm['kind'], { shouldValidate: true });
              // Sites are always manual; force membership back to manual.
              if (v === 'site') {
                setValue('membership', 'manual', { shouldValidate: true });
              }
            }}
          />
        </FormField>

        <FormField label="Subtype" hint="Optional. For example: Environment, Workload, OS family.">
          <input type="text" {...register('subtype')} style={inputStyle} />
        </FormField>

        <FormField
          label="Membership"
          error={formState.errors.membership?.message}
          hint={
            kind === 'site'
              ? 'Sites assign hosts manually.'
              : 'Auto membership populates from OS family capability detection.'
          }
        >
          <Select
            ariaLabel="Membership"
            value={membership}
            width="100%"
            options={[
              { value: 'manual', label: 'Manual' },
              { value: 'auto', label: 'Auto (OS family)' },
            ]}
            onChange={(v) =>
              setValue('membership', v as CreateForm['membership'], { shouldValidate: true })
            }
          />
        </FormField>

        {membership === 'auto' && (
          <FormField
            label="OS family"
            error={formState.errors.match_family?.message}
            hint="For example: rhel, ubuntu, debian."
          >
            <input type="text" {...register('match_family')} style={inputStyle} />
          </FormField>
        )}

        {serverError && (
          <div style={{ marginTop: 12 }}>
            <Callout tier="crit">{serverError}</Callout>
          </div>
        )}
      </form>
    </Modal>
  );
}

// ── shared ─────────────────────────────────────────────────────────

function StateMsg({ kind, message }: { kind: 'loading' | 'error' | 'empty'; message?: string }) {
  const color = kind === 'error' ? 'var(--ow-crit)' : 'var(--ow-fg-3)';
  const text =
    message ??
    (kind === 'loading'
      ? 'Loading…'
      : kind === 'error'
        ? 'Failed to load groups'
        : 'No groups yet');
  return (
    <div
      role={kind === 'error' ? 'alert' : 'status'}
      style={{ color, fontSize: 13, padding: '24px 0' }}
    >
      {text}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  height: 32,
  width: '100%',
  padding: '0 10px',
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-0)',
  fontFamily: 'inherit',
  fontSize: 13,
};
