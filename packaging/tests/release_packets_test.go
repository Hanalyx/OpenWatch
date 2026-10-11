// @spec release-packets

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// F1, F3 and D1 evidence packets (release-packets). The behavior lives in
// scripts/release_packets.py and release/prep/packets/, and is driven by
// scripts/test_release_packets.py against a simulated server, one unittest
// class per criterion. The suite runs once; each criterion checks its class
// passed in full and names the cases a reviewer relies on. AC-06, the SQL
// against the migrated schema, is internal/scanruns/release_readings_test.go.

var (
	releasePacketsOnce   sync.Once
	releasePacketsOut    []byte
	releasePacketsErr    error
	releasePacketsPassed map[string]int
	releasePacketsCases  map[string]bool
)

func requireReleasePackets(t *testing.T, class string, want int, cases ...string) {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "git")
	haveTool(t, "tar")
	dir := appDir(t)
	releasePacketsOnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_packets.py"))
		cmd.Dir = dir
		releasePacketsOut, releasePacketsErr = cmd.CombinedOutput()
		releasePacketsPassed = map[string]int{}
		releasePacketsCases = map[string]bool{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.(\w+)\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(releasePacketsOut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				releasePacketsPassed[m[1]]++
				releasePacketsCases[m[1]+"."+m[2]] = true
			}
		}
	})
	if releasePacketsErr != nil {
		t.Fatalf("scripts/test_release_packets.py: %v\n%s", releasePacketsErr, tailOf(releasePacketsOut, 40))
	}
	if got := releasePacketsPassed[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
	for _, c := range cases {
		if !releasePacketsCases[class+"."+c] {
			t.Errorf("%s.%s did not pass", class, c)
		}
	}
}

// @ac AC-01
// AC-01: F1 reads the captain's scan, read-only, into a packet and a blank skeleton.
func TestReleasePackets_F1ReadsTheScan(t *testing.T) {
	t.Run("release-packets/AC-01", func(t *testing.T) {
		requireReleasePackets(t, "F1Packet", 3,
			"test_a_scan_becomes_a_packet_and_a_skeleton_with_blank_human_fields",
			"test_every_query_is_read_only_and_binds_the_scan_id")
	})
}

// @ac AC-02
// AC-02: F1 writes no packet for a bad scan id, artifact, reading or ordering.
func TestReleasePackets_F1Refuses(t *testing.T) {
	t.Run("release-packets/AC-02", func(t *testing.T) {
		requireReleasePackets(t, "F1Refusals", 7,
			"test_a_malformed_scan_id_is_refused_before_contact",
			"test_inconsistent_records_write_no_packet_and_keep_the_capture",
			"test_a_scan_queued_before_step_8_finished_is_refused")
	})
}

// @ac AC-03
// AC-03: F3 reads the scan variables by schema, with the token kept on the server.
func TestReleasePackets_F3ReadsTheVariables(t *testing.T) {
	t.Run("release-packets/AC-03", func(t *testing.T) {
		requireReleasePackets(t, "F3Packet", 8,
			"test_an_empty_list_is_the_blank_panel_and_fails",
			"test_a_field_of_the_wrong_type_fails_the_schema_check",
			"test_a_token_file_that_is_not_root_only_never_reaches_curl",
			"test_the_token_never_appears_in_any_evidence")
	})
}

// @ac AC-04
// AC-04: D1 runs the skeleton generator from a clean checker commit, and adds no verdict.
func TestReleasePackets_D1Skeleton(t *testing.T) {
	t.Run("release-packets/AC-04", func(t *testing.T) {
		requireReleasePackets(t, "D1Packet", 5,
			"test_the_skeleton_is_the_capture_and_every_verdict_stays_pending",
			"test_a_generator_that_fills_a_verdict_or_a_signature_is_refused")
	})
}

// @ac AC-05
// AC-05: explicit timeouts, and the server scripts change nothing.
func TestReleasePackets_StaysReadOnly(t *testing.T) {
	t.Run("release-packets/AC-05", func(t *testing.T) {
		requireReleasePackets(t, "PacketBoundaries", 3,
			"test_the_server_scripts_change_nothing")
	})
}
