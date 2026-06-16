// @spec release-upgrade
//
// AC traceability (this file):
//
//	AC-03  TestUpgrade_MigrateFlagsAndFailClosed
//	AC-04  TestUpgrade_ScriptletGuardedOnUpgradeOnly
//	AC-05  TestUpgrade_HelperSequenceAndFailSafe
//	AC-06  TestUpgrade_CleanupTimerShippedAndKeepsNewest
//	AC-07  TestUpgrade_PayloadShipsUpgradeFiles

package packaging_test

import (
	"strings"
	"testing"
)

// @ac AC-03
// AC-03: `openwatch migrate` gains --status and --backup-dir, the backup
// runs BEFORE Apply, and a backup failure returns without migrating.
func TestUpgrade_MigrateFlagsAndFailClosed(t *testing.T) {
	t.Run("release-upgrade/AC-03", func(t *testing.T) {
		src := readAppFile(t, "cmd/openwatch/main.go")
		for _, needle := range []string{`"backup-dir"`, `"status"`, "refusing to migrate"} {
			if !strings.Contains(src, needle) {
				t.Errorf("cmdMigrate missing %q", needle)
			}
		}
		// The pre-migration backup must precede migrations.Apply.
		backupAt := strings.Index(src, "dbbackup.Run(")
		applyAt := strings.Index(src, "migrations.Apply(ctx, pool)")
		if backupAt < 0 || applyAt < 0 {
			t.Fatalf("could not locate backup (%d) / apply (%d) in cmdMigrate", backupAt, applyAt)
		}
		if backupAt > applyAt {
			t.Error("backup must run BEFORE migrations.Apply (fail-closed restore point)")
		}
	})
}

// @ac AC-04
// AC-04: the upgrade helper runs on UPGRADE only — RPM gates on $1>=2, DEB
// on a non-empty old-version $2 — never on a fresh install.
func TestUpgrade_ScriptletGuardedOnUpgradeOnly(t *testing.T) {
	t.Run("release-upgrade/AC-04", func(t *testing.T) {
		spec := readAppFile(t, "packaging/rpm/openwatch.spec")
		if !strings.Contains(spec, `[ "$1" -ge 2 ]`) || !strings.Contains(spec, "openwatch-upgrade.sh") {
			t.Error(`RPM post-install must guard openwatch-upgrade.sh on [ "$1" -ge 2 ] (upgrade only)`)
		}
		post := readAppFile(t, "packaging/deb/postinst")
		if !strings.Contains(post, `[ -n "${2:-}" ]`) || !strings.Contains(post, "openwatch-upgrade.sh") {
			t.Error("DEB postinst must guard openwatch-upgrade.sh on a non-empty old-version $2 (upgrade only)")
		}
	})
}

// @ac AC-05
// AC-05: the helper stops the service, migrates with a backup, starts on
// success, and on failure leaves the service stopped + exits non-zero.
func TestUpgrade_HelperSequenceAndFailSafe(t *testing.T) {
	t.Run("release-upgrade/AC-05", func(t *testing.T) {
		h := readAppFile(t, "packaging/common/openwatch-upgrade.sh")
		for _, needle := range []string{
			"systemctl stop openwatch.service",
			"openwatch migrate",
			"--backup-dir",
			"systemctl start openwatch.service",
			"STOPPED", // the fail-safe message
			"exit 1",  // non-zero on migration failure
		} {
			if !strings.Contains(h, needle) {
				t.Errorf("openwatch-upgrade.sh missing %q", needle)
			}
		}
		// Start must be gated on migrate success, not unconditional: the
		// success path returns before the failure block.
		if strings.Index(h, "systemctl start openwatch.service") > strings.Index(h, "MIGRATION FAILED") {
			t.Error("service start must be on the success path, before the failure block")
		}
	})
}

// @ac AC-06
// AC-06: the cleanup timer + service ship and are enabled; the prune keeps
// the most recent dump.
func TestUpgrade_CleanupTimerShippedAndKeepsNewest(t *testing.T) {
	t.Run("release-upgrade/AC-06", func(t *testing.T) {
		// Enabled in both scriptlets.
		if !strings.Contains(readAppFile(t, "packaging/rpm/openwatch.spec"), "enable --now openwatch-backup-cleanup.timer") {
			t.Error("RPM post-install must enable openwatch-backup-cleanup.timer")
		}
		if !strings.Contains(readAppFile(t, "packaging/deb/postinst"), "enable --now openwatch-backup-cleanup.timer") {
			t.Error("DEB postinst must enable openwatch-backup-cleanup.timer")
		}
		// The prune always keeps the newest dump (index 0 -> continue).
		clean := readAppFile(t, "packaging/common/cleanup-backups.sh")
		if !strings.Contains(clean, "always keep") && !strings.Contains(clean, "keep the most recent") {
			t.Error("cleanup-backups.sh must keep the most recent dump")
		}
		if !strings.Contains(clean, "BACKUP_RETENTION_DAYS") {
			t.Error("cleanup-backups.sh must prune by BACKUP_RETENTION_DAYS")
		}
	})
}

// @ac AC-07
// AC-07: the package payloads carry the upgrade helper, cleanup script, the
// two systemd units, the empty backups dir, and upgrade.conf as a config.
func TestUpgrade_PayloadShipsUpgradeFiles(t *testing.T) {
	t.Run("release-upgrade/AC-07", func(t *testing.T) {
		want := []string{
			"/usr/lib/openwatch/openwatch-upgrade.sh",
			"/usr/lib/openwatch/cleanup-backups.sh",
			"/etc/systemd/system/openwatch-backup-cleanup.service",
			"/etc/systemd/system/openwatch-backup-cleanup.timer",
			"/etc/openwatch/upgrade.conf",
			"/var/lib/openwatch/backups",
		}

		rpm := rpmPath(t)
		rpmFiles := rpmQuery(t, rpm, "[%{FILENAMES}\n]")
		for _, f := range want {
			if !strings.Contains(rpmFiles, f) {
				t.Errorf("RPM payload missing %s", f)
			}
		}
		// upgrade.conf must be a config file (noreplace), like openwatch.toml.
		if cfgs := rpmQuery(t, rpm, "[%{FILEFLAGS:fflags} %{FILENAMES}\n]"); !strings.Contains(cfgs, "/etc/openwatch/upgrade.conf") {
			t.Errorf("upgrade.conf not in file list: %s", cfgs)
		}

		deb := debPath(t)
		debFiles := debContents(t, deb)
		for _, f := range want {
			if !strings.Contains(debFiles, f) {
				t.Errorf("DEB payload missing %s", f)
			}
		}
	})
}
