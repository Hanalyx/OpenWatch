// @spec system-scheduler
//
// AC traceability (this file):
//   AC-16  TestNoFrameworkInScheduler_V2

package scheduler

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// @ac AC-16
// AC-16: source-inspection — JobPayload has no FrameworkID field;
// NewService has no defaultFramework parameter; Dispatch's body map
// does not contain the "framework_id" key. Confirms the v2.0.0
// architectural correction is materially in place, not just spec'd.
func TestNoFrameworkInScheduler_V2(t *testing.T) {
	t.Run("system-scheduler/AC-16", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)

		// 1. JobPayload has no FrameworkID field.
		if _, ok := reflect.TypeOf(JobPayload{}).FieldByName("FrameworkID"); ok {
			t.Error("JobPayload still has FrameworkID — v2.0.0 removed it")
		}

		// 2. service.go does not declare DefaultFramework on Service.
		serviceSrc, err := os.ReadFile(filepath.Join(dir, "service.go"))
		if err != nil {
			t.Fatalf("read service.go: %v", err)
		}
		if regexp.MustCompile(`(?m)^\s+DefaultFramework\s+string`).MatchString(string(serviceSrc)) {
			t.Error("service.go still declares DefaultFramework on Service")
		}

		// 3. NewService signature does not include defaultFramework param.
		if regexp.MustCompile(`func NewService\([^)]*defaultFramework`).MatchString(string(serviceSrc)) {
			t.Error("NewService still accepts a defaultFramework parameter")
		}

		// 4. Dispatch's enqueued body map does not contain the
		//    literal "framework_id" key. (The string may appear in
		//    a doc comment — that's allowed.)
		// Look for the JSONB body construction specifically.
		bodyMapRe := regexp.MustCompile(`body\s*:=\s*map\[string\]any\{[^}]*"framework_id"`)
		if bodyMapRe.MatchString(string(serviceSrc)) {
			t.Error("Dispatch's body map still contains framework_id key — v2.0.0 forbids")
		}

		// 5. hmac.go's Encode does not reference FrameworkID.
		hmacSrc, err := os.ReadFile(filepath.Join(dir, "hmac.go"))
		if err != nil {
			t.Fatalf("read hmac.go: %v", err)
		}
		// Allow comments to mention removed history. The struct
		// field assignment p.FrameworkID would be the violation.
		if strings.Contains(string(hmacSrc), "p.FrameworkID") ||
			strings.Contains(string(hmacSrc), "fid := []byte(p.FrameworkID)") {
			t.Error("hmac.go's Encode still references p.FrameworkID")
		}
	})
}
