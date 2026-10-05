package server

import "testing"

// Temporary: proves on PR #909 that a failing internal/server test turns
// "Quality + security gates" red. Reverted by the next commit.
func TestCISplitProbe_FailsOnPurpose(t *testing.T) {
	t.Fatal("deliberate failure: CI split failure-path probe")
}
