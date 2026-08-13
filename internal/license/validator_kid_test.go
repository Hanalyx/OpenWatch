// @spec system-license-validation
//
// AC traceability:
// @ac AC-24  (TestVerify_KidDoesNotOpenDeprecatedSlot)
// @ac AC-30  (TestVerify_KidSelectsCurrent)
// @ac AC-25  (TestVerify_KidPrevSetsUsingPrevKey)
// @ac AC-26  (TestVerify_NoKidUnchanged)
// @ac AC-27  (TestVerify_UnusableKidFallsBack)
// @ac AC-28  (TestKeyID_Derivation)
// @ac AC-29  (TestKeyID_StableAndDistinct)
// @ac AC-31  (TestVerify_MismatchedKidIsRecorded)
// @ac AC-32  (TestLoadJWT_MismatchedKidReachesTheAuditTrail)

package license

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/golang-jwt/jwt/v5"
)

// signJWTWithKid mints a license JWT signed with priv, carrying kid in the JWT
// header when kid is not empty. The package's signJWT reads one fixed testdata
// key and cannot set a header, so the kid tests need their own minter.
func signJWTWithKid(t *testing.T, c claims, kid string, priv ed25519.PrivateKey) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// testKeyPrivate loads the testdata signing key, the private half of the key
// installTestKeyring puts in the current slot. signJWT reads the same file but
// keeps the key to itself, and the audit test has to sign with a kid header.
func testKeyPrivate(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "license-privkey-test.pem"))
	if err != nil {
		t.Fatalf("read test priv: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block in testdata/license-privkey-test.pem")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse test priv: %v", err)
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("testdata key is %T, not ed25519", keyAny)
	}
	return priv
}

// newKeypair generates an Ed25519 keypair for a test ring slot. Key generation
// for the shipped binary is offline and founder-owned, so the prev and
// deprecated slots are built here rather than committed as PEM files under
// keys/.
func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return pub, priv
}

// fullRing is a keyring with all three slots filled by distinct keys, plus the
// private half of each so a test can sign as any slot. Every other test in this
// package uses a ring whose prev and deprecated slots are nil, where "the
// fallback still works" and "there was only ever one key" look identical.
type fullRing struct {
	ring           *publicKeyRing
	currentPriv    ed25519.PrivateKey
	prevPriv       ed25519.PrivateKey
	deprecatedPriv ed25519.PrivateKey
}

func newFullRing(t *testing.T) fullRing {
	t.Helper()
	curPub, curPriv := newKeypair(t)
	prevPub, prevPriv := newKeypair(t)
	depPub, depPriv := newKeypair(t)
	return fullRing{
		ring: &publicKeyRing{
			current:    curPub,
			prev:       prevPub,
			deprecated: depPub,
		},
		currentPriv:    curPriv,
		prevPriv:       prevPriv,
		deprecatedPriv: depPriv,
	}
}

// ed25519SPKIPrefix is the fixed 12-byte DER header on an Ed25519
// SubjectPublicKeyInfo: an outer SEQUENCE, an inner SEQUENCE holding OID
// 1.3.101.112, then a BIT STRING with no unused bits. The 32 raw key bytes
// follow it, for 44 bytes total.
var ed25519SPKIPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// independentKeyID computes the key id by a different route than KeyID takes.
// KeyID calls x509.MarshalPKIXPublicKey; this builds the same DER from the
// fixed prefix. Calling the same marshaller would only prove the
// implementation equals itself, and a shared bug in that step would cancel out
// on both sides. TestKeyID_Derivation checks the two routes agree.
func independentKeyID(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	der := make([]byte, 0, len(ed25519SPKIPrefix)+len(pub))
	der = append(der, ed25519SPKIPrefix...)
	der = append(der, pub...)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// @ac AC-30
// AC-30: a kid naming the current key verifies as Valid with UsingPrevKey
// false. The ring holds three distinct keys, so this is the named slot being
// used, not the only slot that existed.
//
// The AC pins the outcome rather than the selection, and deliberately. A kid
// that misses falls back (C-17) and reaches the same outcome, so direct
// selection is not observable from outside Verify. The outcome is what a caller
// can see.
func TestVerify_KidSelectsCurrent(t *testing.T) {
	t.Run("system-license-validation/AC-30", func(t *testing.T) {
		fr := newFullRing(t)
		jwtBlob := signJWTWithKid(t, validClaims(), KeyID(fr.ring.current), fr.currentPriv)

		lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify (kid names current): %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("result = %s, want valid; a kid naming the current slot must verify", result)
		}
		if lic.UsingPrevKey {
			t.Error("UsingPrevKey = true on a current-key license; using_prev_key would warn " +
				"about a rotation that has not happened")
		}
	})
}

// @ac AC-25
// AC-25: a prev-key license selected by kid still sets License.UsingPrevKey.
// Before kid selection, that flag was set only by the failed-current-then-retry
// sequence (AC-03), which direct selection never runs. The flag is surfaced as
// using_prev_key, so losing it here means a declared field reports the opposite
// of the truth: the deployment runs on a rotated-out key and the warning
// surface stays dark.
func TestVerify_KidPrevSetsUsingPrevKey(t *testing.T) {
	t.Run("system-license-validation/AC-25", func(t *testing.T) {
		fr := newFullRing(t)
		jwtBlob := signJWTWithKid(t, validClaims(), KeyID(fr.ring.prev), fr.prevPriv)

		lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify (kid names prev): %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("result = %s, want valid; a kid naming the prev slot must verify", result)
		}
		if !lic.UsingPrevKey {
			t.Error("UsingPrevKey = false, want true; kid selection reached the prev key, " +
				"but using_prev_key reports the deployment is on the current key")
		}
	})
}

// @ac AC-24
// AC-24: a kid naming the deprecated slot does not open that slot. Naming a key
// is a request, not an authorization. A thumbprint-to-key map that hands back
// any ring member on a match would turn the dev-only slot into a production
// one, which is the whole security content of this change.
func TestVerify_KidDoesNotOpenDeprecatedSlot(t *testing.T) {
	t.Run("system-license-validation/AC-24", func(t *testing.T) {
		fr := newFullRing(t)
		jwtBlob := signJWTWithKid(t, validClaims(), KeyID(fr.ring.deprecated), fr.deprecatedPriv)

		// Production: the flag is off, so naming the deprecated key does not
		// reach it. Exactly signature_invalid, which is what the trial order
		// gives. Accepting any non-valid result would also pass on a
		// malformed_jwt, and that would mean the token was refused before the
		// gate was ever consulted.
		lic, result, _ := Verify(jwtBlob, fr.ring, VerifyOptions{})
		if result != VerifySignatureInvalid {
			t.Errorf("AllowDeprecatedKey false: result = %s, want signature_invalid; "+
				"a kid naming the deprecated key must not unlock it", result)
		}
		if lic != nil {
			t.Errorf("AllowDeprecatedKey false: license = %+v, want nil", lic)
		}

		// Dev mode: the same token, now permitted.
		lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{AllowDeprecatedKey: true})
		if err != nil {
			t.Fatalf("AllowDeprecatedKey true: Verify: %v", err)
		}
		if result != VerifyValid {
			t.Fatalf("AllowDeprecatedKey true: result = %s, want valid", result)
		}
		if lic.UsingPrevKey {
			t.Error("AllowDeprecatedKey true: UsingPrevKey = true, want false; the " +
				"deprecated slot is not the prev slot")
		}
	})
}

// @ac AC-27
// AC-27: a kid the verifier cannot use falls back to the trial order. The
// issuer stamps kid before any verifier reads it, so a header naming something
// this binary does not hold must not cost the customer their license. Every key
// in the ring is already a trusted anchor, so kid is a hint about which one,
// not an extra trust decision.
func TestVerify_UnusableKidFallsBack(t *testing.T) {
	t.Run("system-license-validation/AC-27", func(t *testing.T) {
		fr := newFullRing(t)
		strangerPub, _ := newKeypair(t)

		cases := []struct {
			name string
			kid  string
		}{
			// A kid no slot in this ring derives.
			{"kid of a key the ring does not hold", KeyID(strangerPub)},
			// A kid naming a real slot that did not sign this token. The
			// verifier must still reach the key that did.
			{"kid of the prev slot on a current-signed license", KeyID(fr.ring.prev)},
			// A slot name is not a key id. KeyID derives from key bytes, so no
			// key ever produces this string.
			{"the literal slot name current", "current"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				jwtBlob := signJWTWithKid(t, validClaims(), tc.kid, fr.currentPriv)
				lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
				if err != nil {
					t.Fatalf("Verify (kid = %q): %v", tc.kid, err)
				}
				if result != VerifyValid {
					t.Fatalf("result = %s, want valid; an unusable kid must fall back to "+
						"the trial order, not refuse a license the ring can verify", result)
				}
				if lic.UsingPrevKey {
					t.Error("UsingPrevKey = true; the current key signed this license, " +
						"and the fallback must report the slot that verified")
				}
			})
		}

		// The fallback keeps reporting the slot that verified, not the slot the
		// header named. Without this, a stale kid could make a rotated-out key
		// look current.
		t.Run("fallback to prev still sets UsingPrevKey", func(t *testing.T) {
			jwtBlob := signJWTWithKid(t, validClaims(), KeyID(strangerPub), fr.prevPriv)
			lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("result = %s, want valid", result)
			}
			if !lic.UsingPrevKey {
				t.Error("UsingPrevKey = false, want true; the prev key verified this license")
			}
		})
	})
}

// @ac AC-31
// AC-31: when the fallback rescues a token whose kid did not name the key that
// verified it, the license says so at License.MismatchedKeyID.
//
// AC-27 makes that rescue succeed. Succeeding silently is the defect this
// criterion exists to catch: an issuer that mislabels every license it mints
// looks exactly like an issuer that labels them correctly.
//
// The two negative cases carry the criterion. A field hardcoded to the
// presented kid passes every positive case on its own.
func TestVerify_MismatchedKidIsRecorded(t *testing.T) {
	t.Run("system-license-validation/AC-31", func(t *testing.T) {
		fr := newFullRing(t)
		strangerPub, _ := newKeypair(t)

		// The three AC-27 shapes. Each is signed by the current key and stamped
		// with a kid that did not name it, so each must carry that exact kid
		// back out.
		recorded := []struct {
			name string
			kid  string
		}{
			{"kid of a key the ring does not hold", KeyID(strangerPub)},
			{"kid of the prev slot on a current-signed license", KeyID(fr.ring.prev)},
			{"the literal slot name current", "current"},
		}
		for _, tc := range recorded {
			t.Run(tc.name, func(t *testing.T) {
				jwtBlob := signJWTWithKid(t, validClaims(), tc.kid, fr.currentPriv)
				lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if result != VerifyValid {
					t.Fatalf("result = %s, want valid", result)
				}
				// The exact string the token presented, not a flag and not a
				// description of it. A consumer has to be able to tell the
				// issuer which label was wrong.
				if lic.MismatchedKeyID != tc.kid {
					t.Errorf("MismatchedKeyID = %q, want %q; the fallback rescued this "+
						"license and reported nothing about the kid that missed",
						lic.MismatchedKeyID, tc.kid)
				}
			})
		}

		// Both fields at once. The fallback lands on prev, so UsingPrevKey is
		// true AND the mislabel is recorded. Neither field may swallow the
		// other: an implementation that stopped recording once it had a
		// rotation to report would pass every case above.
		t.Run("a prev-key fallback records the mislabel and the rotation", func(t *testing.T) {
			presented := KeyID(strangerPub)
			jwtBlob := signJWTWithKid(t, validClaims(), presented, fr.prevPriv)
			lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("result = %s, want valid", result)
			}
			if lic.MismatchedKeyID != presented {
				t.Errorf("MismatchedKeyID = %q, want %q", lic.MismatchedKeyID, presented)
			}
			if !lic.UsingPrevKey {
				t.Error("UsingPrevKey = false, want true; the prev key verified this license")
			}
		})

		// Negative one: the kid named the key that verified. Nothing was
		// mislabeled, so there is nothing to report.
		t.Run("empty when the kid named the verifying key", func(t *testing.T) {
			jwtBlob := signJWTWithKid(t, validClaims(), KeyID(fr.ring.current), fr.currentPriv)
			lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("result = %s, want valid", result)
			}
			if lic.MismatchedKeyID != "" {
				t.Errorf("MismatchedKeyID = %q, want empty; this kid named the key that "+
					"verified, so reporting a mismatch accuses a correct issuer",
					lic.MismatchedKeyID)
			}
		})

		// Negative two: no kid at all. A license minted before the issuer
		// stamped kid must not look mislabeled.
		t.Run("empty when the token carries no kid", func(t *testing.T) {
			jwtBlob := signJWTWithKid(t, validClaims(), "", fr.currentPriv)
			lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("result = %s, want valid", result)
			}
			if lic.MismatchedKeyID != "" {
				t.Errorf("MismatchedKeyID = %q, want empty; the token presented no kid, "+
					"so no kid can have missed", lic.MismatchedKeyID)
			}
		})
	})
}

// @ac AC-32
// AC-32: the mislabel reaches the audit trail, not just the License struct.
//
// This test reads the emitted license.installed detail map. AC-31 already
// covers the struct field, and a value a Go caller can read but no auditor ever
// sees leaves an issuer that mislabels every license it mints invisible (C-19).
func TestLoadJWT_MismatchedKidReachesTheAuditTrail(t *testing.T) {
	t.Run("system-license-validation/AC-32", func(t *testing.T) {
		// The keyring holds the testdata key alone, which is the key signJWT
		// signs with. Any kid other than that key's own is therefore a kid that
		// did not select the key that verified.
		verifying := testKeyPublic(t, "license-privkey-test.pem")

		t.Run("present when the kid did not select the verifying key", func(t *testing.T) {
			installTestKeyring(t)
			rec := installAuditRecorder(t)
			strangerPub, _ := newKeypair(t)
			presented := KeyID(strangerPub)

			jwtBlob := signJWTWithKid(t, validClaims(), presented, testKeyPrivate(t))
			result, err := LoadJWT(jwtBlob, VerifyOptions{})
			if err != nil {
				t.Fatalf("LoadJWT: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("result = %s, want valid; the fallback must still install the license", result)
			}

			// EmitLoadResult is what the boot and SIGHUP paths call once the
			// load returns. LoadJWT itself emits nothing.
			st := CurrentState()
			if st == nil || st.License == nil {
				t.Fatal("no license installed")
			}
			EmitLoadResult(context.Background(), "test", result, st.License, nil)

			detail, ok := rec.detailFor(t, audit.LicenseInstalled)
			if !ok {
				t.Fatal("no license.installed event; a load that succeeded emitted nothing")
			}
			// The presented kid itself, not a boolean. Hanalyx has to be able to
			// tell which thumbprint the issuer stamped wrongly.
			if got := detail["mismatched_key_id"]; got != presented {
				t.Errorf("mismatched_key_id = %v, want %q; the mislabel stayed on the "+
					"License struct and never reached an auditor", got, presented)
			}
		})

		t.Run("absent when the kid selected the verifying key", func(t *testing.T) {
			installTestKeyring(t)
			rec := installAuditRecorder(t)

			jwtBlob := signJWTWithKid(t, validClaims(), KeyID(verifying), testKeyPrivate(t))
			result, err := LoadJWT(jwtBlob, VerifyOptions{})
			if err != nil {
				t.Fatalf("LoadJWT: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("result = %s, want valid", result)
			}

			st := CurrentState()
			if st == nil || st.License == nil {
				t.Fatal("no license installed")
			}
			EmitLoadResult(context.Background(), "test", result, st.License, nil)

			detail, ok := rec.detailFor(t, audit.LicenseInstalled)
			if !ok {
				t.Fatal("no license.installed event")
			}
			// Absent or empty. Reporting a mislabel that did not happen would
			// send Hanalyx after a correctly behaving issuer.
			if got, present := detail["mismatched_key_id"]; present && got != "" {
				t.Errorf("mismatched_key_id = %v, want absent or empty; this kid named "+
					"the key that verified", got)
			}
			// The control: the event carries its usual detail, so the check
			// above is reading a populated map rather than an empty one.
			if _, present := detail["using_prev_key"]; !present {
				t.Error("license.installed detail has no using_prev_key; the absence " +
					"assertion above proves nothing against an empty detail map")
			}
		})
	})
}

// @ac AC-26
// AC-26: a license with no kid header behaves exactly as it did before kid
// selection existed. This is a regression pin, not a smoke test, so the ring
// holds three distinct keys. Run against a ring with nil prev and deprecated
// slots, the fallback cases cannot fail.
func TestVerify_NoKidUnchanged(t *testing.T) {
	t.Run("system-license-validation/AC-26", func(t *testing.T) {
		fr := newFullRing(t)

		// The AC-01 case with a populated ring: the current key verifies first
		// and claims nothing about rotation.
		t.Run("current key verifies and does not claim prev", func(t *testing.T) {
			jwtBlob := signJWTWithKid(t, validClaims(), "", fr.currentPriv)
			lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("result = %s, want valid", result)
			}
			if lic.UsingPrevKey {
				t.Error("UsingPrevKey = true on a current-key license")
			}
		})

		// The AC-03 case: current fails, prev catches it, and the flag is set.
		// This is the path every license in the field takes after a rotation.
		t.Run("prev key verifies and sets UsingPrevKey", func(t *testing.T) {
			jwtBlob := signJWTWithKid(t, validClaims(), "", fr.prevPriv)
			lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("result = %s, want valid; the no-kid fallback to prev is the "+
					"path a rotated deployment takes", result)
			}
			if !lic.UsingPrevKey {
				t.Error("UsingPrevKey = false on a prev-key license")
			}
		})

		// The deprecated slot stays behind the dev-mode flag on the no-kid path
		// too. Adding kid selection must not have loosened it.
		t.Run("deprecated key stays behind the dev-mode flag", func(t *testing.T) {
			jwtBlob := signJWTWithKid(t, validClaims(), "", fr.deprecatedPriv)

			lic, result, _ := Verify(jwtBlob, fr.ring, VerifyOptions{})
			if result != VerifySignatureInvalid {
				t.Errorf("AllowDeprecatedKey false: result = %s, want signature_invalid", result)
			}
			if lic != nil {
				t.Errorf("AllowDeprecatedKey false: license = %+v, want nil", lic)
			}

			lic, result, err := Verify(jwtBlob, fr.ring, VerifyOptions{AllowDeprecatedKey: true})
			if err != nil {
				t.Fatalf("AllowDeprecatedKey true: Verify: %v", err)
			}
			if result != VerifyValid {
				t.Fatalf("AllowDeprecatedKey true: result = %s, want valid", result)
			}
			if lic.UsingPrevKey {
				t.Error("AllowDeprecatedKey true: UsingPrevKey = true, want false")
			}
		})
	})
}

// @ac AC-28
// AC-28: KeyID is the base64url SHA-256 of the key's SPKI DER, with no padding.
// The offline issuer stamps kid with its own implementation of this rule, so a
// derivation that is merely stable and distinct can still disagree with every
// license ever minted. Hex, retained padding, or hashing the raw 32 key bytes
// instead of the 44-byte SPKI DER all pass a self-comparison and then fail in
// the field.
func TestKeyID_Derivation(t *testing.T) {
	t.Run("system-license-validation/AC-28", func(t *testing.T) {
		pubA, _ := newKeypair(t)
		pubB, _ := newKeypair(t)

		t.Run("matches an independently derived digest", func(t *testing.T) {
			for _, pub := range []ed25519.PublicKey{pubA, pubB} {
				want := independentKeyID(t, pub)
				if got := KeyID(pub); got != want {
					t.Errorf("KeyID = %q, want %q (base64url with no padding, over "+
						"sha256 of the SPKI DER)", got, want)
				}
			}
		})

		// The hand-built DER is the independent route, so pin that it is the
		// same DER the standard marshaller produces. If this ever fails, the
		// check above is measuring against the wrong bytes.
		t.Run("the hand-built SPKI DER is the standard one", func(t *testing.T) {
			der, err := x509.MarshalPKIXPublicKey(pubA)
			if err != nil {
				t.Fatalf("marshal SPKI: %v", err)
			}
			hand := append(append([]byte{}, ed25519SPKIPrefix...), pubA...)
			if string(der) != string(hand) {
				t.Fatalf("hand-built DER %x does not match x509.MarshalPKIXPublicKey %x", hand, der)
			}
			if len(der) != 44 {
				t.Errorf("SPKI DER is %d bytes, want 44", len(der))
			}
		})

		// Hashing the raw key bytes rather than the SPKI DER is the likely
		// wrong turn, and it produces a string of the same length and alphabet.
		t.Run("hashes the SPKI DER, not the raw key bytes", func(t *testing.T) {
			raw := sha256.Sum256(pubA)
			if got := KeyID(pubA); got == base64.RawURLEncoding.EncodeToString(raw[:]) {
				t.Error("KeyID hashes the raw 32 key bytes; the issuer hashes the 44-byte SPKI DER")
			}
		})

		// 32 digest bytes encode to 43 base64 characters plus one pad. The pad
		// must be absent and the alphabet must be the URL-safe one, or the
		// value is not safe unescaped in a JWT header.
		t.Run("base64url with no padding", func(t *testing.T) {
			id := KeyID(pubA)
			if len(id) != 43 {
				t.Errorf("len(KeyID) = %d, want 43", len(id))
			}
			if strings.ContainsAny(id, "=+/") {
				t.Errorf("KeyID = %q, want base64url with no padding (no '=', '+' or '/')", id)
			}
		})
	})
}

// @ac AC-29
// AC-29: KeyID is stable for a given key and distinct for different keys.
func TestKeyID_StableAndDistinct(t *testing.T) {
	t.Run("system-license-validation/AC-29", func(t *testing.T) {
		pubA, _ := newKeypair(t)
		pubB, _ := newKeypair(t)
		idA := KeyID(pubA)

		t.Run("stable across calls", func(t *testing.T) {
			if again := KeyID(pubA); again != idA {
				t.Errorf("KeyID is not stable: %q then %q", idA, again)
			}
			// A separate slice over the same bytes must give the same id.
			// Anything keyed off the slice header rather than the contents
			// passes the call-twice check and fails here.
			copied := make(ed25519.PublicKey, len(pubA))
			copy(copied, pubA)
			if got := KeyID(copied); got != idA {
				t.Errorf("KeyID over a copy of the same bytes = %q, want %q", got, idA)
			}
		})

		t.Run("distinct between keys", func(t *testing.T) {
			if idB := KeyID(pubB); idB == idA {
				t.Errorf("two different keys share a key id: %q", idA)
			}
		})
	})
}
