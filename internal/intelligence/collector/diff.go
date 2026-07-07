package collector

// Diff returns the ordered list of Events the (prior, current)
// snapshot pair should emit. Pure function: no side effects.
//
// Detection order: packages, listening ports, group memberships,
// users, services, mountpoints, kernel, reboot state, config hashes.
// Spec AC-06, AC-07, AC-08, AC-13 enforce specific patterns.
//
// The "privileged groups" set is locked here — wheel + sudo + admin.
// Future per-deployment groups (e.g., "developers") that should be
// privileged-tracked land in policy, not in this set.
var privilegedGroups = map[string]bool{
	"wheel": true,
	"sudo":  true,
	"admin": true,
}

// Diff returns the list of changes between prior and current. Order
// of returned events follows the detection order above so a stable
// audit trail emerges from a stable snapshot pair.
func Diff(prior, current Snapshot) []Event {
	var events []Event

	// --- Packages -----------------------------------------------------------
	for name, currentVersion := range current.Packages {
		priorVersion, was := prior.Packages[name]
		switch {
		case !was:
			events = append(events, Event{
				Code:     CodeSystemPackageInstalled,
				Severity: "info",
				Detail:   map[string]any{"name": name, "version": currentVersion},
			})
		case priorVersion != currentVersion:
			events = append(events, Event{
				Code:     CodeSystemPackageUpdated,
				Severity: "info",
				Detail: map[string]any{
					"name":    name,
					"prior":   priorVersion,
					"current": currentVersion,
				},
			})
		}
	}
	for name := range prior.Packages {
		if _, still := current.Packages[name]; !still {
			events = append(events, Event{
				Code:     CodeSystemPackageRemoved,
				Severity: "medium",
				Detail:   map[string]any{"name": name},
			})
		}
	}

	// --- Listening ports ---------------------------------------------------
	priorPorts := portSet(prior.ListeningPorts)
	for _, p := range current.ListeningPorts {
		key := portKey(p)
		if !priorPorts[key] {
			events = append(events, Event{
				Code:     CodeSecurityPortOpened,
				Severity: "high",
				Detail: map[string]any{
					"port":     p.Port,
					"protocol": p.Protocol,
				},
			})
		}
	}

	// --- Privileged group additions ----------------------------------------
	for group, members := range current.Groups {
		if !privilegedGroups[group] {
			continue
		}
		priorSet := stringSet(prior.Groups[group])
		for _, user := range members {
			if !priorSet[user] {
				events = append(events, Event{
					Code:     CodeAccountUserPrivilegedGroupAdd,
					Severity: "critical",
					Detail:   map[string]any{"user": user, "group": group},
				})
			}
		}
	}

	// --- Users: lock + new + deleted ---------------------------------------
	for name, u := range current.Users {
		prev, had := prior.Users[name]
		switch {
		case !had:
			events = append(events, Event{
				Code:     CodeAccountUserCreated,
				Severity: "medium",
				Detail:   map[string]any{"user": name, "uid": u.UID},
			})
		case !prev.Locked && u.Locked:
			events = append(events, Event{
				Code:     CodeAccountUserLocked,
				Severity: "medium",
				Detail:   map[string]any{"user": name},
			})
		case prev.Locked && !u.Locked:
			events = append(events, Event{
				Code:     CodeAccountUserUnlocked,
				Severity: "info",
				Detail:   map[string]any{"user": name},
			})
		}

		// Password expiry is TIME-based: the shadow fields don't change
		// between cycles, wall-clock time crosses PasswordExpiresAt. Fire
		// account.password.expired once, on the flip (prior not-expired ->
		// current expired), deduped by the append-only log's UNIQUE key.
		// "Expiring soon" (a warn window) is owned by the daily sweep, which
		// carries the configurable threshold; the diff only records the hard
		// expiry crossing. Spec AC-03.
		if passwordExpired(u, current.CollectedAt) && !passwordExpired(prev, prior.CollectedAt) {
			events = append(events, Event{
				Code:     CodeAccountPasswordExpired,
				Severity: "high",
				Detail:   map[string]any{"user": name, "expires_at": u.PasswordExpiresAt},
			})
		}
	}
	for name := range prior.Users {
		if _, still := current.Users[name]; !still {
			events = append(events, Event{
				Code:     CodeAccountUserDeleted,
				Severity: "medium",
				Detail:   map[string]any{"user": name},
			})
		}
	}

	// --- Services ----------------------------------------------------------
	for unit, state := range current.Services {
		prevState, had := prior.Services[unit]
		if !had {
			continue // first-seen services don't emit; would be too noisy
		}
		if prevState == state {
			continue
		}
		switch state {
		case "active":
			events = append(events, Event{
				Code:     CodeSystemServiceStarted,
				Severity: "info",
				Detail:   map[string]any{"unit": unit},
			})
		case "inactive":
			events = append(events, Event{
				Code:     CodeSystemServiceStopped,
				Severity: "info",
				Detail:   map[string]any{"unit": unit},
			})
		case "failed":
			events = append(events, Event{
				Code:     CodeSystemServiceFailed,
				Severity: "high",
				Detail:   map[string]any{"unit": unit},
			})
		}
	}

	// --- Filesystem --------------------------------------------------------
	for mp, source := range current.Mountpoints {
		if _, had := prior.Mountpoints[mp]; !had {
			events = append(events, Event{
				Code:     CodeSystemFilesystemMounted,
				Severity: "info",
				Detail:   map[string]any{"mountpoint": mp, "source": source},
			})
		}
	}
	for mp := range prior.Mountpoints {
		if _, still := current.Mountpoints[mp]; !still {
			events = append(events, Event{
				Code:     CodeSystemFilesystemUnmounted,
				Severity: "medium",
				Detail:   map[string]any{"mountpoint": mp},
			})
		}
	}

	// --- Kernel ------------------------------------------------------------
	if prior.KernelRelease != "" && current.KernelRelease != "" &&
		prior.KernelRelease != current.KernelRelease {
		events = append(events, Event{
			Code:     CodeSystemKernelUpdated,
			Severity: "medium",
			Detail: map[string]any{
				"prior":   prior.KernelRelease,
				"current": current.KernelRelease,
			},
		})
	}

	// --- Reboot state ------------------------------------------------------
	if !prior.RebootRequired && current.RebootRequired {
		events = append(events, Event{
			Code:     CodeSystemRebootRequired,
			Severity: "medium",
			Detail:   map[string]any{},
		})
	}
	// Uptime fell below prior cycle's value → reboot completed.
	if prior.UptimeSeconds > 0 && current.UptimeSeconds > 0 &&
		current.UptimeSeconds+10 < prior.UptimeSeconds {
		events = append(events, Event{
			Code:     CodeSystemRebootCompleted,
			Severity: "info",
			Detail: map[string]any{
				"prior_uptime":   prior.UptimeSeconds,
				"current_uptime": current.UptimeSeconds,
			},
		})
	}

	// --- Config hashes -----------------------------------------------------
	for path, currHash := range current.ConfigHashes {
		priorHash, had := prior.ConfigHashes[path]
		if had && priorHash != currHash {
			events = append(events, Event{
				Code:     CodeSystemConfigChanged,
				Severity: "high",
				Detail: map[string]any{
					"path":         path,
					"prior_hash":   priorHash,
					"current_hash": currHash,
				},
			})
		}
	}

	return events
}

func portKey(p ListeningPort) string {
	return p.Protocol + "|" + p.Address + "|" + strconvItoa(p.Port)
}

func portSet(ports []ListeningPort) map[string]bool {
	out := make(map[string]bool, len(ports))
	for _, p := range ports {
		out[portKey(p)] = true
	}
	return out
}

func stringSet(xs []string) map[string]bool {
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		out[x] = true
	}
	return out
}

// strconvItoa avoids an import-cycle in tests where a hot helper is
// needed. Equivalent to strconv.Itoa for small int values.
func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	neg := n < 0
	if neg {
		n = -n
	}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
