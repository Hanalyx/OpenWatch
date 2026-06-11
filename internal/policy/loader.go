package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

// LoadFile reads a policy file from disk, validates the envelope and
// rules, verifies the signature against the active keyring, and (on
// success) atomically swaps the active state to include the new version.
//
// Returns LoadOutcome telling the admin endpoint what happened. On any
// failure the prior state is preserved per spec C-07.
//
// Spec system-policy AC-02, AC-03, AC-04, AC-05, AC-06.
func LoadFile(ctx context.Context, pool *pgxpool.Pool, path string) (LoadOutcome, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		emitInvalid(ctx, "", "", []string{"read_error: " + err.Error()})
		return LoadInvalid, err
	}
	return LoadBytes(ctx, pool, raw)
}

// LoadBytes is the file-content-driven path used by both LoadFile and
// tests that mint a policy in-memory.
func LoadBytes(ctx context.Context, pool *pgxpool.Pool, raw []byte) (LoadOutcome, error) {
	var env Envelope
	if err := yaml.Unmarshal(raw, &env); err != nil {
		emitInvalid(ctx, "", "", []string{"parse_error: " + err.Error()})
		return LoadInvalid, fmt.Errorf("policy: parse: %w", err)
	}
	return LoadEnvelope(ctx, pool, raw, env)
}

// LoadEnvelope applies the full validation pipeline to a parsed
// envelope + its raw bytes (raw is needed for signature verify + hash).
func LoadEnvelope(ctx context.Context, pool *pgxpool.Pool, raw []byte, env Envelope) (LoadOutcome, error) {
	// 1) Verify signature (or allow unsigned in dev mode).
	devMode := os.Getenv("OPENWATCH_DEV_MODE") == "true"
	warnings := []string{}
	if env.Signature.Value == "" {
		if !devMode {
			emitInvalid(ctx, env.PolicyType, env.Version, []string{"signature_missing"})
			return LoadInvalid, ErrUnsignedInProduction
		}
		warnings = append(warnings, "unsigned_dev_mode")
	} else if err := verifySignature(raw, env); err != nil {
		emitInvalid(ctx, env.PolicyType, env.Version, []string{"signature_invalid: " + err.Error()})
		return LoadInvalid, fmt.Errorf("policy: signature: %w", err)
	}

	// 2) Validate envelope.
	if !knownType(env.PolicyType) {
		emitInvalid(ctx, env.PolicyType, env.Version, []string{"unknown_policy_type"})
		return LoadInvalid, fmt.Errorf("policy: unknown type %q", env.PolicyType)
	}
	newSemver, err := parseSemver(env.Version)
	if err != nil {
		emitInvalid(ctx, env.PolicyType, env.Version, []string{"version_invalid: " + err.Error()})
		return LoadInvalid, fmt.Errorf("policy: version: %w", err)
	}

	// 3) Monotonic version check vs. current state.
	st := Get()
	if st == nil {
		st = Init()
	}
	prevVersion := st.Versions[env.PolicyType]
	if prevVersion != "" {
		oldSemver, err := parseSemver(prevVersion)
		if err == nil && cmpSemver(newSemver, oldSemver) < 0 {
			emitInvalid(ctx, env.PolicyType, env.Version,
				[]string{fmt.Sprintf("version regression: %s < %s", env.Version, prevVersion)})
			return LoadInvalid, fmt.Errorf("policy: version regression %s < %s", env.Version, prevVersion)
		}
	}

	// 4) Source-hash unchanged short-circuit.
	hash := hashBytes(raw)
	if st.Sources[env.PolicyType] == hash {
		return LoadUnchanged, nil
	}

	// 5) Type-specific validation + payload assembly.
	newState := cloneState(st)
	newState.Versions[env.PolicyType] = env.Version
	newState.Sources[env.PolicyType] = hash
	newState.SignedBy[env.PolicyType] = env.Metadata.SignedBy
	newState.LoadedAt = time.Now()
	newState.Warnings = warnings

	if env.PolicyType == TypeAlertThresholds {
		thresholds, validationErrs := parseAlertThresholds(env.Rules)
		if len(validationErrs) > 0 {
			emitInvalid(ctx, env.PolicyType, env.Version, validationErrs)
			return LoadInvalid, &LoaderError{Type: env.PolicyType, Errors: validationErrs}
		}
		newState.AlertThresholds = thresholds
	}

	// 6) Atomic swap.
	setState(newState)

	// 7) History snapshot.
	if pool != nil {
		if err := writeHistory(ctx, pool, env.PolicyType, env.Version, hash, env.Metadata.SignedBy); err != nil {
			// History write failure does not roll back the load — the
			// state is already swapped. Log via audit so operators see it.
			emitInvalid(ctx, env.PolicyType, env.Version, []string{"history_write_failed: " + err.Error()})
		}
	}

	// 8) Audit emit (spec C-06).
	emitLoaded(ctx, env.PolicyType, env.Version, prevVersion, warnings)
	return LoadLoaded, nil
}

// cloneState produces a shallow copy of s with new map instances so the
// active pointer's referent is not mutated.
func cloneState(s *State) *State {
	out := &State{
		Versions:        make(map[Type]string, len(s.Versions)),
		Sources:         make(map[Type]string, len(s.Sources)),
		SignedBy:        make(map[Type]string, len(s.SignedBy)),
		AlertThresholds: s.AlertThresholds,
		LoadedAt:        s.LoadedAt,
	}
	for k, v := range s.Versions {
		out.Versions[k] = v
	}
	for k, v := range s.Sources {
		out.Sources[k] = v
	}
	for k, v := range s.SignedBy {
		out.SignedBy[k] = v
	}
	return out
}

// verifySignature canonicalizes the document (strips the signature
// block) and verifies Ed25519 against the active keyring.
func verifySignature(raw []byte, env Envelope) error {
	if env.Signature.Algorithm != "" && env.Signature.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported algorithm %q", env.Signature.Algorithm)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature.Value)
	if err != nil {
		return fmt.Errorf("base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("signature length mismatch")
	}
	canonical, err := canonicalizeForSigning(raw)
	if err != nil {
		return err
	}
	ring := activeKeyring()
	if ring == nil || ring.current == nil {
		return errors.New("no admin public key loaded")
	}
	if !ed25519.Verify(ring.current, canonical, sig) {
		return errors.New("signature verify failed")
	}
	return nil
}

// canonicalizeForSigning strips the signature block from the YAML document
// and re-serializes the remaining envelope. The signer signs over this
// canonical form so verification works regardless of YAML whitespace.
func canonicalizeForSigning(raw []byte) ([]byte, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("canon parse: %w", err)
	}
	stripSignatureNode(&node)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&node); err != nil {
		return nil, fmt.Errorf("canon encode: %w", err)
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

func stripSignatureNode(n *yaml.Node) {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		stripSignatureNode(n.Content[0])
		return
	}
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i]
		if key.Kind == yaml.ScalarNode && key.Value == "signature" {
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return
		}
	}
}

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func knownType(t Type) bool {
	switch t {
	case TypeExceptions, TypeApprovals, TypeSchedules, TypeAlertThresholds, TypeRemediation:
		return true
	}
	return false
}

type semver struct{ Major, Minor, Patch int }

func parseSemver(s string) (semver, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("not semver: %q", s)
	}
	var sv semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, fmt.Errorf("not semver: %q", s)
		}
		switch i {
		case 0:
			sv.Major = n
		case 1:
			sv.Minor = n
		case 2:
			sv.Patch = n
		}
	}
	return sv, nil
}

func cmpSemver(a, b semver) int {
	if a.Major != b.Major {
		return a.Major - b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor - b.Minor
	}
	return a.Patch - b.Patch
}

func parseAlertThresholds(rules map[string]any) (AlertThresholds, []string) {
	errs := []string{}
	pull := func(key string) int {
		v, ok := rules[key]
		if !ok {
			errs = append(errs, "missing_rule: "+key)
			return -1
		}
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		default:
			errs = append(errs, "rule_type: "+key+" must be integer")
			return -1
		}
	}
	t := AlertThresholds{
		CriticalBelow: pull("critical_below"),
		HighBelow:     pull("high_below"),
		MediumBelow:   pull("medium_below"),
	}
	check := func(name string, v int) {
		if v < 0 || v > 100 {
			errs = append(errs, name+"_out_of_range: 0..100")
		}
	}
	check("critical_below", t.CriticalBelow)
	check("high_below", t.HighBelow)
	check("medium_below", t.MediumBelow)
	if len(errs) == 0 && !(t.CriticalBelow <= t.HighBelow && t.HighBelow <= t.MediumBelow) {
		errs = append(errs, "thresholds_out_of_order: critical_below <= high_below <= medium_below required")
	}
	return t, errs
}

// writeHistory inserts a row into policy_history. Called only on
// successful state swap.
func writeHistory(ctx context.Context, pool *pgxpool.Pool, t Type, version, hash, signedBy string) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	// Mark prior active row (if any) as superseded.
	_, err = pool.Exec(ctx,
		`UPDATE policy_history SET superseded_at = now()
		  WHERE policy_type = $1 AND superseded_at IS NULL`,
		string(t))
	if err != nil {
		return fmt.Errorf("supersede: %w", err)
	}
	signedByPtr := &signedBy
	if signedBy == "" {
		signedByPtr = nil
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO policy_history (id, policy_type, version, source_hash, signed_by)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, string(t), version, hash, signedByPtr)
	if err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	return nil
}
