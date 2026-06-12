// Live end-to-end verification of the production scan chain against a
// real fleet host: LoadRules -> api.New(NewScanner, in-memory
// TransportFactory) -> Scan -> outcome mapping. No OpenWatch database
// involved — this exercises the engine, the SSH transport, and the
// kensa->OpenWatch field copy in isolation.
//
// Gated on environment (skips otherwise):
//
//	OPENWATCH_LIVE_SCAN_ADDR  target host (ip or name), port 22 assumed
//	OPENWATCH_LIVE_SCAN_USER  ssh username
//	OPENWATCH_LIVE_SCAN_KEY   path to the private key file
//	OPENWATCH_KENSA_RULES_DIR rule corpus (empty = kensa-rules default)
//
// Run: OPENWATCH_LIVE_SCAN_ADDR=... go test ./internal/kensa/ -run LiveScan -v -timeout 20m
package kensa

import (
	"context"
	"os"
	"testing"
	"time"

	kensaapi "github.com/Hanalyx/kensa/api"
	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/credential"
	owssh "github.com/Hanalyx/openwatch/internal/ssh"
)

func TestLiveScan_EndToEnd(t *testing.T) {
	addr := os.Getenv("OPENWATCH_LIVE_SCAN_ADDR")
	user := os.Getenv("OPENWATCH_LIVE_SCAN_USER")
	keyPath := os.Getenv("OPENWATCH_LIVE_SCAN_KEY")
	if addr == "" || user == "" || keyPath == "" {
		t.Skip("set OPENWATCH_LIVE_SCAN_{ADDR,USER,KEY} to run the live scan test")
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	cred := &credential.Credential{
		Username:   user,
		AuthMethod: credential.AuthSSHKey,
		PrivateKey: string(keyPEM),
	}

	rules, err := pkgkensa.LoadRules(os.Getenv("OPENWATCH_KENSA_RULES_DIR"), nil, nil)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	t.Logf("corpus: %d rules", len(rules))

	factory := &TransportFactory{
		Resolve: func(context.Context, uuid.UUID) (*credential.Credential, error) { return cred, nil },
		Mode:    owssh.ModeTOFU,
		Store:   owssh.NewMemoryStore(),
	}
	svc, err := newScanService(factory)
	if err != nil {
		t.Fatalf("newScanService: %v", err)
	}

	host := kensaapi.HostConfig{
		Hostname: addr,
		Port:     22,
		Sudo:     true,
		FleetID:  uuid.NewString(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	started := time.Now()
	res, err := svc.Scan(ctx, host, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	t.Logf("scan completed in %s", time.Since(started).Round(time.Second))

	if len(res.Outcomes) == 0 {
		t.Fatal("Scan returned zero outcomes")
	}

	// Map through the production field copy and tally.
	mapped := mapOutcomes(res.Outcomes)
	var pass, fail, skipped, errored, multiRef int
	for _, o := range mapped {
		switch o.Status {
		case StatusPass:
			pass++
		case StatusFail:
			fail++
		case StatusSkipped:
			skipped++
		case StatusError:
			errored++
		default:
			t.Errorf("rule %s: status %q outside the closed enum", o.RuleID, o.Status)
		}
		for fw, controls := range o.FrameworkRefs {
			if len(controls) > 1 {
				multiRef++
				_ = fw
				break
			}
		}
		if len(o.Evidence) == 0 {
			t.Errorf("rule %s: empty evidence document", o.RuleID)
		}
	}
	t.Logf("outcomes: %d total — pass=%d fail=%d skipped=%d error=%d; rules with multi-control framework refs=%d",
		len(mapped), pass, fail, skipped, errored, multiRef)

	if pass == 0 && fail == 0 {
		t.Error("no pass/fail verdicts at all — engine likely never reached the host")
	}
	if multiRef == 0 {
		t.Error("no rule carried multiple controls within one framework — R6 multi-value path unexercised (corpus regression?)")
	}
}
