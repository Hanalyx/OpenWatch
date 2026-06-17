// @spec system-connection-profile
//
// AC traceability (this file):
//
//	AC-04  TestOrderedAuthMethods_PreferenceNotExclusion / TestAuthObserver_RecordsLast
//	AC-13  TestKeyboardInteractive_PasswordReplay

package ssh

import (
	"context"
	"testing"
	"time"
)

// @ac AC-04
// AC-04: every available auth method is offered (preference orders, does
// not exclude), so a stale hint still falls back within the one handshake.
func TestOrderedAuthMethods_PreferenceNotExclusion(t *testing.T) {
	t.Run("system-connection-profile/AC-04", func(t *testing.T) {
		both, _ := generateEd25519CredAndAuthKey(t)
		both.Password = "pw" // promote to a key+password credential // pragma: allowlist secret

		// Every method offered regardless of which is preferred. A key+password
		// credential offers three: publickey, password, and keyboard-interactive
		// (the password family is two methods — see AC-13).
		for _, prefer := range []string{"", PreferKey, PreferPassword} {
			m, err := orderedAuthMethods(both, prefer, &authObserver{})
			if err != nil {
				t.Fatalf("prefer %q: %v", prefer, err)
			}
			if len(m) != 3 {
				t.Errorf("prefer %q: %d methods, want 3 (preference is order, not exclusion)", prefer, len(m))
			}
		}

		// Key-only offers one (publickey); password-only offers two (password +
		// keyboard-interactive).
		keyOnly := *both
		keyOnly.Password = ""
		if m, _ := orderedAuthMethods(&keyOnly, "", &authObserver{}); len(m) != 1 {
			t.Errorf("key-only: %d methods, want 1", len(m))
		}
		pwOnly := *both
		pwOnly.PrivateKey = ""
		if m, _ := orderedAuthMethods(&pwOnly, "", &authObserver{}); len(m) != 2 {
			t.Errorf("password-only: %d methods, want 2 (password + keyboard-interactive)", len(m))
		}
	})
}

// @ac AC-04
// AC-04 (observation): the observer reports the last method attempted,
// which after a successful handshake is the one that authenticated.
func TestAuthObserver_RecordsLast(t *testing.T) {
	t.Run("system-connection-profile/AC-04", func(t *testing.T) {
		o := &authObserver{}
		if o.Last() != "" {
			t.Errorf("fresh observer Last = %q, want empty", o.Last())
		}
		o.note(PreferKey)
		o.note(PreferPassword) // key rejected, password accepted -> last wins
		if o.Last() != PreferPassword {
			t.Errorf("Last = %q, want %q", o.Last(), PreferPassword)
		}
	})
}

// @ac AC-13
// AC-13: the keyboard-interactive challenge replays the password for hidden
// (non-echoed) PAM prompts only, never for echoed/visible prompts, and notes
// the password method only when it actually supplied the password. This is
// what lets a password credential authenticate against a hardened server that
// serves passwords via PAM keyboard-interactive (PasswordAuthentication no).
func TestKeyboardInteractive_PasswordReplay(t *testing.T) {
	t.Run("system-connection-profile/AC-13", func(t *testing.T) {
		const pw = "s3cret-pw" // pragma: allowlist secret

		run := func(questions []string, echos []bool) (answers []string, noted bool) {
			ch := passwordKbdChallenge(pw, func() { noted = true })
			answers, err := ch("", "", questions, echos)
			if err != nil {
				t.Fatalf("challenge error: %v", err)
			}
			return answers, noted
		}

		// A single hidden "Password:" prompt is answered with the password.
		if a, noted := run([]string{"Password: "}, []bool{false}); len(a) != 1 || a[0] != pw || !noted {
			t.Errorf("hidden prompt: answers=%q noted=%v, want [%q] true", a, noted, pw)
		}
		// An echoed/visible prompt is NEVER answered with the password.
		if a, noted := run([]string{"One-time token: "}, []bool{true}); len(a) != 1 || a[0] != "" || noted {
			t.Errorf("echoed prompt: answers=%q noted=%v, want [\"\"] false (password must not leak)", a, noted)
		}
		// Mixed: password to the hidden prompt, empty to the visible one.
		if a, noted := run([]string{"Password: ", "Show this: "}, []bool{false, true}); len(a) != 2 || a[0] != pw || a[1] != "" || !noted {
			t.Errorf("mixed prompts: answers=%q noted=%v, want [%q \"\"] true", a, noted, pw)
		}
		// An informational challenge with no questions supplies nothing and does
		// not record a password attempt.
		if a, noted := run(nil, nil); len(a) != 0 || noted {
			t.Errorf("no questions: answers=%q noted=%v, want [] false", a, noted)
		}
	})
}

// @ac AC-13
// AC-13 (end to end): a password credential authenticates against a server
// that offers ONLY keyboard-interactive — no bare "password" method — which is
// the hardened prod config (PasswordAuthentication no + PAM keyboard-interactive)
// that produced "ssh: unable to authenticate ... [none] ... no supported
// methods remain". Before keyboard-interactive support this dial failed; now it
// succeeds via the replayed password.
func TestDial_KeyboardInteractiveOnlyServer(t *testing.T) {
	t.Run("system-connection-profile/AC-13", func(t *testing.T) {
		host, port, hostKey, _ := startTestServer(t, testServerOpts{kbdInteractivePassword: "tester-pw-1"})
		store := NewMemoryStore()
		_ = store.Put(host, hostKey) // strict: pre-seed the host key

		client, err := Dial(context.Background(), host, port, passwordCred("tester-pw-1"),
			DialOptions{Mode: ModeStrict, Store: store, Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("dial against keyboard-interactive-only server: %v", err)
		}
		_ = client.Close()
	})
}
