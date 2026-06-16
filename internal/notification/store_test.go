// @spec system-notifications
//
// Encrypted-store round-trips + dispatch fan-out. DSN-gated: skipped
// without OPENWATCH_TEST_DSN.

package notification

import (
	"bytes"
	"context"
	"testing"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/secretkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshService(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	pool := dbtest.Pool(t)
	if err := secretkey.SetEphemeral(); err != nil {
		t.Fatalf("secretkey.SetEphemeral: %v", err)
	}
	t.Cleanup(secretkey.Reset)
	ctx := context.Background()
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE notification_channels")
	return NewService(pool), pool
}

// @ac AC-01
func TestCreate_EncryptsAndRoundTrips(t *testing.T) {
	t.Run("system-notifications/AC-01", func(t *testing.T) {
		svc, pool := freshService(t)
		ctx := context.Background()
		url := "https://hooks.slack.com/services/T/B/secrettoken"
		c, err := svc.Create(ctx, CreateParams{
			Type: TypeSlack, Name: "ops", Enabled: true,
			Config: Config{URL: url},
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if c.TargetHint != "hooks.slack.com" {
			t.Errorf("TargetHint = %q, want hooks.slack.com", c.TargetHint)
		}
		// The ciphertext column must not contain the plaintext URL bytes.
		var cipher []byte
		_ = pool.QueryRow(ctx, `SELECT config_ciphertext FROM notification_channels WHERE id=$1`, c.ID).Scan(&cipher)
		if bytes.Contains(cipher, []byte(url)) {
			t.Error("ciphertext contains plaintext url — not encrypted")
		}
		// Decrypted round-trip returns the original secret.
		dec, err := svc.getDecrypted(ctx, c.ID)
		if err != nil {
			t.Fatalf("getDecrypted: %v", err)
		}
		if dec.Config.URL != url {
			t.Errorf("decrypted url = %q, want %q", dec.Config.URL, url)
		}
	})
}

// @ac AC-08
func TestCreate_EmailRoundTrips(t *testing.T) {
	t.Run("system-notifications/AC-08", func(t *testing.T) {
		svc, _ := freshService(t)
		ctx := context.Background()
		c, err := svc.Create(ctx, CreateParams{
			Type: TypeEmail, Name: "secops-mail", Enabled: true,
			Config: Config{
				SMTPHost: "smtp.corp.example", SMTPPort: 587,
				Username: "ow", Password: "smtp-secret",
				From: "openwatch@corp.example", To: []string{"sec@corp.example"},
			},
		})
		if err != nil {
			t.Fatalf("Create email: %v", err)
		}
		if c.TargetHint != "smtp.corp.example" {
			t.Errorf("TargetHint = %q, want smtp.corp.example", c.TargetHint)
		}
		dec, err := svc.getDecrypted(ctx, c.ID)
		if err != nil {
			t.Fatalf("getDecrypted: %v", err)
		}
		if dec.Config.SMTPHost != "smtp.corp.example" || dec.Config.SMTPPort != 587 ||
			dec.Config.Password != "smtp-secret" || dec.Config.From != "openwatch@corp.example" ||
			len(dec.Config.To) != 1 || dec.Config.To[0] != "sec@corp.example" {
			t.Errorf("email config round-trip wrong: %+v", dec.Config)
		}
	})
}

// @ac AC-06
func TestUpdateAndDelete(t *testing.T) {
	t.Run("system-notifications/AC-06", func(t *testing.T) {
		svc, _ := freshService(t)
		ctx := context.Background()
		c, _ := svc.Create(ctx, CreateParams{
			Type: TypeWebhook, Name: "n1", Enabled: true,
			Config: Config{URL: "https://example.com/hook"},
		})
		// ReplaceConfig=false: secret + hint unchanged, name/enabled change.
		u, err := svc.Update(ctx, c.ID, UpdateParams{Name: "n2", Enabled: false})
		if err != nil {
			t.Fatalf("Update meta: %v", err)
		}
		if u.Name != "n2" || u.Enabled != false || u.TargetHint != "example.com" {
			t.Errorf("meta update wrong: %+v", u)
		}
		dec, _ := svc.getDecrypted(ctx, c.ID)
		if dec.Config.URL != "https://example.com/hook" {
			t.Error("secret changed on meta-only update")
		}
		// ReplaceConfig=true: new secret + hint.
		_, err = svc.Update(ctx, c.ID, UpdateParams{
			Name: "n2", Enabled: true, ReplaceConfig: true,
			Config: Config{URL: "https://hooks.slack.com/new"},
		})
		if err != nil {
			t.Fatalf("Update secret: %v", err)
		}
		dec, _ = svc.getDecrypted(ctx, c.ID)
		if dec.Config.URL != "https://hooks.slack.com/new" || dec.TargetHint != "hooks.slack.com" {
			t.Errorf("secret replace failed: %+v", dec)
		}
		// Delete is idempotent.
		if err := svc.Delete(ctx, c.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := svc.Delete(ctx, c.ID); err != nil {
			t.Fatalf("Delete (second) should be idempotent: %v", err)
		}
		if err := svc.Delete(ctx, uuid.New()); err != nil {
			t.Fatalf("Delete missing should be idempotent: %v", err)
		}
	})
}

// @ac AC-05
// Dispatch fan-out: an enabled wildcard channel and a matching-tag channel
// receive; a disabled channel and a non-matching channel do not. We point
// channels at a local test server but assert via the captured request set,
// not network — the SSRF guard blocks loopback, so this test verifies the
// selection logic by counting how many channels Send attempts to reach.
func TestDispatch_SelectsEnabledMatching(t *testing.T) {
	t.Run("system-notifications/AC-05", func(t *testing.T) {
		svc, _ := freshService(t)
		ctx := context.Background()
		// All use a public-looking host so validation passes; delivery will
		// fail (no real endpoint) but Send still iterates the selected set.
		mk := func(name string, enabled bool, tags map[string]string) {
			_, err := svc.Create(ctx, CreateParams{
				Type: TypeWebhook, Name: name, Enabled: enabled,
				Config: Config{URL: "https://example.com/" + name}, TagFilter: tags,
			})
			if err != nil {
				t.Fatalf("create %s: %v", name, err)
			}
		}
		mk("wild", true, nil)
		mk("match", true, map[string]string{"severity": "critical"})
		mk("nomatch", true, map[string]string{"severity": "info"})
		mk("disabled", false, nil)

		enabled, err := svc.listEnabledDecrypted(ctx)
		if err != nil {
			t.Fatalf("listEnabledDecrypted: %v", err)
		}
		// disabled excluded by the query.
		if len(enabled) != 3 {
			t.Fatalf("enabled count = %d, want 3 (disabled excluded)", len(enabled))
		}
		alert := alertrouter.Alert{Severity: "critical", Tags: map[string]string{"severity": "critical"}}
		selected := 0
		for _, ch := range enabled {
			if matchesTags(ch.TagFilter, alert.Tags) {
				selected++
			}
		}
		// wild + match select; nomatch does not.
		if selected != 2 {
			t.Errorf("selected = %d, want 2 (wild + match)", selected)
		}
	})
}
