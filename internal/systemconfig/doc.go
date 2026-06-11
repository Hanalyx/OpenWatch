// Package systemconfig is the runtime config store. Operator-tunable
// values land here as one row per key in the system_config table,
// with JSONB values typed by per-config-domain structs.
//
// Spec: app/specs/services/connectivity-config.spec.yaml (the first
// consumer). Future config domains (compliance scheduler, retention,
// alert thresholds) land alongside without schema changes.
//
// Key namespaces are managed inline (one per config struct). The
// Get/Set helpers operate on raw JSONB; consumers wrap them with a
// typed Load/Save (e.g., LoadConnectivity, SetConnectivity).
//
// Defaults: when no row exists for a key, Load* returns the baked-in
// defaults the calling consumer defines. No "initial seed" migration
// — the absence of a row is itself a meaningful state ("never
// configured, defaults apply").
//
// Audit: every Set emits audit.SystemConfigChanged with
// {config_key, old_value, new_value, changed_by}. The old_value is
// captured in the same transaction so concurrent writes can't race
// it into incoherence.
package systemconfig
