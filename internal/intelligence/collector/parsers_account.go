package collector

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

// shadowEpoch is day 0 for the /etc/shadow date fields (days since
// 1970-01-01 UTC). PasswordExpiresAt = shadowEpoch + (lstchg+max) days.
var shadowEpoch = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

// ParsePasswdShadow parses /etc/passwd + /etc/shadow into AccountFacts.
//
// Each passwd line: user:x:uid:gid:gecos:home:shell.
// Each shadow line: user:pwd:lastchange:min:max:warn:inactive:expire:reserved.
//
// Lock detection: shadow.pwd starts with "!" or "*". Empty pwd ("") is
// NOT locked — it's a password-less account, which is a different
// (worse) state but not a lockout per se.
func ParsePasswdShadow(passwd, shadow []byte) (AccountFacts, error) {
	facts := AccountFacts{Users: map[string]UserSnapshot{}}

	for _, raw := range bytes.Split(passwd, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		u := UserSnapshot{UID: uid, Locked: false}
		// GECOS (f5) and login shell (f7) — surfaced on the human-account
		// cards. Absent on malformed short lines; left empty then.
		if len(fields) > 4 {
			u.Gecos = strings.TrimSpace(fields[4])
		}
		if len(fields) > 6 {
			u.Shell = strings.TrimSpace(fields[6])
		}
		facts.Users[fields[0]] = u
	}

	for _, raw := range bytes.Split(shadow, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		// Full split (was SplitN ",3", which discarded the aging fields):
		// user:pwd:lastchange:min:max:warn:inactive:expire:reserved.
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		user, pwd := fields[0], fields[1]
		u, ok := facts.Users[user]
		if !ok {
			// Shadow-only users (rare); seed with zero UID and the locked flag.
			u = UserSnapshot{}
		}
		if isShadowLocked(pwd) {
			u.Locked = true
		}
		// Password aging: lstchg (f3) + max (f5). Empty string ⇒ nil
		// (unset / unknown), preserved distinctly from a literal 0.
		u.LastChangeDays = atoiPtr(fields, 2)
		u.MaxDays = atoiPtr(fields, 4)
		// Derived expiry: only when a real policy is in force AND the
		// last-change date is known. Pure function of the shadow fields
		// (no clock), so the diff/sweep compare it against CollectedAt.
		if PasswordPolicyActive(u.MaxDays) && u.LastChangeDays != nil {
			exp := shadowEpoch.AddDate(0, 0, *u.LastChangeDays+*u.MaxDays)
			u.PasswordExpiresAt = &exp
		}
		facts.Users[user] = u
	}
	return facts, nil
}

// atoiPtr parses fields[i] as an int, returning nil when the index is out
// of range or the value is empty/non-numeric (shadow fields are often
// blank). A literal "0" parses to a non-nil *0.
func atoiPtr(fields []string, i int) *int {
	if i >= len(fields) {
		return nil
	}
	s := strings.TrimSpace(fields[i])
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &n
}

func isShadowLocked(pwd string) bool {
	if pwd == "" {
		return false
	}
	switch pwd[0] {
	case '!', '*':
		return true
	}
	return false
}
