package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Hanalyx/openwatch/internal/config"
	"github.com/Hanalyx/openwatch/internal/credprotect/fingerprint"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/secretkey"
)

// Exit codes of `openwatch credential-key`. Success means a keyring that
// is initialized, structurally sound and readable with the active key; an
// uninitialized keyring is reported apart, never as success.
const (
	credentialKeyOK             = 0
	credentialKeyFailed         = 1
	credentialKeyUsage          = 2
	credentialKeyNotInitialized = 3
)

// cmdCredentialKey runs `openwatch credential-key rewrap|verify` against
// the configured database and credential key (spec
// system-credential-protection C-17).
func cmdCredentialKey(cfg *config.Config, args []string, stdout, stderr *os.File) int {
	if len(args) == 0 || (args[0] != "rewrap" && args[0] != "verify") {
		fmt.Fprintln(stderr, "usage: openwatch credential-key rewrap --previous-key-file PATH | verify")
		return credentialKeyUsage
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "openwatch credential-key: invalid config:\n%v\n", err)
		return credentialKeyFailed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pool, err := db.NewPool(ctx, cfg.Database.DSN, cfg.Database.MaxConnections)
	if err != nil {
		fmt.Fprintf(stderr, "openwatch credential-key: connect %s: %v\n", config.RedactDSN(cfg.Database.DSN), err)
		return credentialKeyFailed
	}
	defer pool.Close()
	return runCredentialKey(ctx, pool, cfg.Identity.CredentialKeyFile, args, stdout, stderr)
}

// runCredentialKey is the command behind cmdCredentialKey, given a database
// and the configured key file.
func runCredentialKey(ctx context.Context, db fingerprint.TxBeginner, activeKeyFile string, args []string,
	stdout, stderr io.Writer) int {
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("credential-key "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	previousFile := ""
	if sub == "rewrap" {
		fs.StringVar(&previousFile, "previous-key-file", "", "the credential key being replaced (required)")
	}
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 {
		return credentialKeyUsage
	}
	if sub == "rewrap" && previousFile == "" {
		fmt.Fprintln(stderr, "openwatch credential-key rewrap: --previous-key-file is required")
		return credentialKeyUsage
	}
	if activeKeyFile == "" {
		fmt.Fprintln(stderr, "openwatch credential-key: identity.credential_key_file is empty")
		return credentialKeyFailed
	}
	current, err := secretkey.ReadFile(activeKeyFile)
	if err != nil {
		fmt.Fprintf(stderr, "openwatch credential-key: %v\n", err)
		return credentialKeyFailed
	}

	var rep fingerprint.Report
	if sub == "verify" {
		rep, err = fingerprint.Verify(ctx, db, current)
	} else {
		previous, perr := secretkey.ReadFile(previousFile)
		if perr != nil {
			fmt.Fprintf(stderr, "openwatch credential-key rewrap: %v\n", perr)
			return credentialKeyFailed
		}
		rep, err = fingerprint.Rewrap(ctx, db, previous, current)
	}
	var u *fingerprint.UnavailableError
	switch {
	case errors.As(err, &u) && u.Cause == fingerprint.CauseNotInitialized:
		fmt.Fprintf(stdout, "openwatch credential-key %s: no keyring exists yet; nothing to %s. %s\n", sub, sub, u.Remedy())
		return credentialKeyNotInitialized
	case err != nil:
		fmt.Fprintf(stderr, "openwatch credential-key %s: %v\n", sub, err)
		return credentialKeyFailed
	}
	switch {
	case sub == "verify":
		fmt.Fprintf(stdout, "openwatch credential-key verify: %d fingerprint key(s) read with the active credential key; "+
			"generation %d, re-wrapped %d time(s)\n", rep.Keys, rep.Generation, rep.WrapEpoch)
	case rep.AlreadyRewrapped:
		fmt.Fprintf(stdout, "openwatch credential-key rewrap: already re-wrapped; %d fingerprint key(s) read with the "+
			"active credential key, nothing changed\n", rep.Keys)
	default:
		fmt.Fprintf(stdout, "openwatch credential-key rewrap: re-wrapped %d fingerprint key(s) with the active "+
			"credential key and read them back\n", rep.Keys)
	}
	return credentialKeyOK
}
