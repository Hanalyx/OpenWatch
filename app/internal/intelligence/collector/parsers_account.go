package collector

import (
	"bytes"
	"strconv"
	"strings"
)

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
		facts.Users[fields[0]] = UserSnapshot{UID: uid, Locked: false}
	}

	for _, raw := range bytes.Split(shadow, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", 3)
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
		facts.Users[user] = u
	}
	return facts, nil
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
